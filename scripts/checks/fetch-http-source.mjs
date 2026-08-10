// fetch-http-source.mjs — build-side HTTP tarball fetch + extract (Phase 8, HTTP-04).
//
// The BUILD-side twin of clone-source.mjs::cloneAndExtract. An io.http.* publish PR
// is sourced from an arbitrary HTTP server (NOT GitHub), so the tarball is treated
// as MORE untrusted than a GitHub one (HTTP-04 posture): redirects are NOT silently
// followed, default TLS validation is never disabled, and extraction runs through
// the SAME WR-06-hardened tar-guard (isSafePath/isSafeEntry) the CLI applies.
//
// Returns the SAME { extractDir, bundleDir, resolvedRef } contract as
// cloneAndExtract so Plan 03's computeEvidence http branch treats both source
// types uniformly downstream. `resolvedRef` = the content SHA-256 of the
// DOWNLOADED tarball bytes (D-06 — HTTP has no git ref; the content pin IS the
// reproducibility anchor).
//
// SECURITY (T-08-REDIRECT/T-08-TLS/T-08-CSHA/T-08-TARGUARD):
//  - redirect: "manual" — a hostile 301/302/307/308 to an attacker tarball is NOT
//    silently followed (Pitfall 4a). Throws naming the URL + redirect target.
//  - default TLS validation — native fetch validates certs; we NEVER set
//    rejectUnauthorized:false (Pitfall 4b).
//  - resolvedRef = sha256(downloaded bytes) — a tampered tarball yields a different
//    SHA; the content pin is the reproducibility anchor (D-06).
//  - extraction runs the WR-06-hardened isSafePath (leading-drive-only, NOT all
//    colons) + isSafeEntry (symlink/hardlink reject) guards. OKF bundles are pure
//    markdown trees — no legitimate use for symlinks.
//
// Why system tar (not the npm `tar` package): registry-repo deliberately stays
// dependency-light (only zod); `node:tar` is NOT a Node built-in and the npm
// `tar` package is not installed here. The existing clone-source.mjs uses the
// system `tar` via execFile — list-then-validate-then-extract. This mirrors that
// (the tar-guard runs over `tar -tzvf` listing BEFORE extraction, defense-in-depth
// with system tar's own `--no-same-owner`).

import { createHash } from "node:crypto";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join, normalize, relative } from "node:path";
import { tmpdir } from "node:os";

const execFileP = promisify(execFile);

// ── WR-06-hardened tar-guard (single source of truth: okfhub-cli/src/lib/source.ts
//    isSafePath:395-409 + isSafeEntry:435-448). Task 03-03 reconciles the registry's
//    clone-source.mjs copy to match these EXACT semantics and exports them so this
//    module imports the shared copy; until then this is byte-equivalent to the CLI. ──

/** Entry type names that represent links (symlinks + hardlinks). */
const LINK_TYPES = new Set(["SymbolicLink", "Link", "symlink", "hardlink"]);

/**
 * Path-traversal guard (WR-06-hardened, vendored from source.ts:395-409). Rejects
 * absolute paths, leading Windows drive letters, and `..` segments. The leading-
 * drive-only check (`/^[a-z]:\//i`) — NOT `includes(":")` — is the WR-06 fix: the
 * old all-colons check rejected legitimate concept filenames containing a colon.
 */
export function isSafePath(entryPath) {
  const n = normalize(entryPath).replace(/\\/g, "/");
  if (n.startsWith("/")) return false; // absolute path
  // WR-06: only reject a LEADING Windows drive letter (e.g. C:/), not any colon.
  if (/^[a-z]:\//i.test(n)) return false; // windows drive letter
  if (n.includes("..")) return false; // traversal
  return !relative(".", n).startsWith("..");
}

/**
 * Reject link entries (symlinks/hardlinks) from tar extraction. OKF bundles are
 * pure markdown trees — no legitimate use for symlinks. Also guards the linkpath
 * against traversal. Mirrors source.ts isSafeEntry:435-448.
 *
 * @param {{type?: string, linkpath?: string, isSymbolicLink?: Function}} entry
 */
export function isSafeEntry(entry) {
  if (typeof entry.type === "string" && LINK_TYPES.has(entry.type)) return false;
  if (typeof entry.isSymbolicLink === "function" && entry.isSymbolicLink()) return false;
  if (entry.linkpath && !isSafePath(entry.linkpath)) return false;
  return true;
}

/**
 * Fetch + extract an HTTP-served tarball. Returns { extractDir, bundleDir,
 * resolvedRef } — the SAME contract cloneAndExtract returns (so Plan 03's
 * computeEvidence treats both source types uniformly). `resolvedRef` = the content
 * SHA-256 of the downloaded tarball bytes (D-06).
 *
 * @param {object} manifest - validated manifest; reads manifest.source.{url, path}.
 * @param {object} [opts] - { fetch } override for unit tests (the DI seam — mirrors
 *   reputation.mjs opts.gh). Production uses native globalThis.fetch.
 * @returns {Promise<{extractDir: string, bundleDir: string, resolvedRef: string}>}
 */
export async function fetchHttpSource(manifest, opts = {}) {
  const fetch = opts.fetch ?? globalThis.fetch;
  if (typeof fetch !== "function") {
    throw new Error("fetchHttpSource: a fetch implementation is required (opts.fetch or globalThis.fetch).");
  }
  const sourceUrl = manifest?.source?.url;
  const sourcePath = manifest?.source?.path ?? "";

  const extractDir = await mkdtemp(join(tmpdir(), "okfhub-http-"));
  const tarballPath = join(extractDir, "source.tar.gz");

  try {
    // (a) Fetch with redirect: "manual" (HTTP-04, T-08-REDIRECT). Arbitrary HTTP
    //     servers get NO implicit redirect trust — unlike the GitHub path which
    //     follows only the expected codeload 302, ANY redirect here is a trap.
    const res = await fetch(sourceUrl, { redirect: "manual" });
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers?.get?.("location") ?? "<no Location header>";
      throw new Error(
        `HTTP source '${sourceUrl}' returned a redirect (status ${res.status}) to '${location}'. okfhub does not follow redirects for HTTP-served bundles (HTTP-04); update the manifest source.url to the direct tarball URL.`,
      );
    }
    if (!res.ok) {
      throw new Error(`Could not access HTTP source '${sourceUrl}' (HTTP ${res.status}).`);
    }

    // (b) Buffer the full response body into a Buffer. Default TLS validation is
    //     NEVER disabled (native fetch validates certs — Pitfall 4b).
    const ab = await res.arrayBuffer();
    const tarballBytes = Buffer.from(ab);
    await writeFile(tarballPath, tarballBytes);

    // (c) resolvedRef = content SHA-256 of the downloaded tarball bytes (D-06 — the
    //     HTTP analog of the git short-SHA; the reproducibility anchor).
    const resolvedRef = createHash("sha256").update(tarballBytes).digest("hex");

    // (d) List entries BEFORE extracting, validate each through the WR-06-hardened
    //     tar-guard, then extract (mirrors clone-source.mjs's list-then-extract —
    //     system tar does not accept a JS filter, so we pre-validate the listing).
    //     `tar -tzvf` emits verbose lines: permissions, owner, size, date, path
    //     (+ ' -> target' for symlinks).
    const { stdout: listing } = await execFileP("tar", ["-tzvf", tarballPath]);
    for (const rawLine of listing.split("\n")) {
      const line = rawLine.trim();
      if (!line) continue;
      // The path is the last whitespace-delimited field; for symlinks/hardlinks it
      // is 'path -> target'. Reject any entry the guard rejects.
      const entryPath = line.split(/\s+/).slice(-1)[0] ?? line;
      const [pathPart, linkTarget] = entryPath.split(" -> ");
      if (!isSafePath(pathPart)) {
        throw new Error(`structure: refusing tarball entry escaping the extract dir: '${pathPart}' (T-08-TARGUARD).`);
      }
      // Reject any symlink/hardlink outright (OKF bundles are pure markdown trees).
      if (linkTarget !== undefined || /^l/i.test(line)) {
        const entry = { type: /^l/i.test(line) ? "SymbolicLink" : "Link", linkpath: linkTarget ?? "" };
        if (!isSafeEntry(entry)) {
          throw new Error(`structure: refusing symlink/hardlink in tarball: '${entryPath}' (T-08-TARGUARD).`);
        }
      }
    }

    // Extract (no-same-owner; system tar refuses unsafe paths by default on ubuntu,
    // but we validated above as defense-in-depth).
    await execFileP("tar", ["-xzf", tarballPath, "-C", extractDir, "--no-same-owner"]);
    await rm(tarballPath, { force: true });

    // (e) Detect the bundle root. HTTP tarballs may have NO top dir (unlike
    //     GitHub's <owner>-<repo>-<sha>/). source.path wins; else a single top-level
    //     dir; else extractDir itself.
    let bundleDir;
    if (sourcePath && sourcePath !== "/") {
      bundleDir = join(extractDir, sourcePath);
    } else {
      const entries = await readdir(extractDir, { withFileTypes: true });
      const topDirs = entries.filter((e) => e.isDirectory());
      const topFiles = entries.filter((e) => e.isFile());
      if (topDirs.length === 1 && topFiles.length === 0) {
        bundleDir = join(extractDir, topDirs[0].name);
      } else {
        bundleDir = extractDir;
      }
    }
    // Assert the bundle root exists (mirror clone-source.mjs L153-156 message).
    try {
      await readdir(bundleDir);
    } catch {
      throw new Error(`structure: manifest source.path '${sourcePath}' not found in the HTTP tarball at '${sourceUrl}'.`);
    }

    return { extractDir, bundleDir, resolvedRef };
  } catch (e) {
    // On any failure, clean up the tempdir (the caller's finally only runs on
    // success since we rethrow). Do not leak the tempdir.
    await rm(extractDir, { recursive: true, force: true }).catch(() => {});
    throw e;
  }
}
