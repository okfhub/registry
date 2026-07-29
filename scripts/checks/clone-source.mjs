#!/usr/bin/env node
// clone-source.mjs — fetch + extract a publish PR's source bundle for the
// structural-identity check (#5, Phase 4 D-02 / VAL-02).
//
// Runs in the CHECK half only (merge-gate-check.yml, GITHUB_TOKEN). Reads the
// pull_request event, finds the io.github.<org>/<name>.json manifest, fetches
// it at the PR head, and downloads the manifest's source tarball. Prints the
// extracted bundleDir absolute path to stdout (consumed by the workflow, which
// exports it as STRUCTURE_BUNDLE_DIR for gate-check.mjs → evaluatePullRequest).
//
// WHY THIS IS A SEPARATE STEP (not inside evaluatePullRequest): the gate logic
// is shared with the merge half, whose registry-scoped App token CANNOT clone
// arbitrary github.com sources (T-04-SCOPE). The clone is check-half-only, so
// it lives here as a distinct entry point the merge half never invokes.
//
// SECURITY (T-06-PAWN / T-04-PATH / T-04-SYM):
//  - Reads the PUBLIC source repo (public bundles only). The GITHUB_TOKEN is
//    fork-PR-safe (no secrets to exfiltrate).
//  - Downloads via the system `curl` (not an untrusted npm dep) and extracts
//    with the system `tar`, then REJECTS any extracted path containing `..` or
//    any symlink/hardlink entry (isSafePath + isSafeEntry, vendored from
//    okfhub-cli/src/lib/source.ts — T-04-PATH / T-04-SYM).
//  - verifyBundle (run downstream) only READS markdown — never eval/execs bundle
//    files (T-06-PAWN).
//  - No `set -x` in the workflow step; this script never echoes the token.
//
// Env contract:
//   GITHUB_TOKEN       — default Actions token (read-only, fork-PR safe)
//   GITHUB_REPOSITORY  — "okfhub/registry"
//   GITHUB_EVENT_PATH  — pull_request event JSON

import { readFile, readdir, rm, mkdir, stat } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join, normalize, relative } from "node:path";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { makeGh } from "./gate-lib.mjs";

const execFileP = promisify(execFile);
const REPO = process.env.GITHUB_REPOSITORY || "okfhub/registry";
const TOKEN = process.env.GITHUB_TOKEN;
const API = process.env.GITHUB_API_URL || "https://api.github.com";

async function readEvent() {
  const p = process.env.GITHUB_EVENT_PATH;
  if (!p) throw new Error("GITHUB_EVENT_PATH not set — clone-source must run inside a GitHub Action.");
  return JSON.parse(await readFile(p, "utf8"));
}

/** Parse owner/repo out of a https://github.com/<owner>/<repo> URL. Mirrors
 *  okfhub-cli/src/lib/source.ts parseGithubUrl. */
function parseGithubUrl(url) {
  const m = /^https:\/\/github\.com\/([^/]+)\/([^/?#]+?)(?:\.git)?(?:[/?#]|$)/.exec(url);
  if (!m) throw new Error(`Manifest source.url '${url}' is not a recognized GitHub URL.`);
  return { owner: m[1], repo: m[2] };
}

/** Fetch the manifest JSON a PR publishes at its head. Returns null if absent. */
async function fetchManifestAtHead(gh, prNumber, filePath) {
  const prRes = await gh(`/repos/${REPO}/pulls/${prNumber}`);
  if (!prRes.ok) throw new Error(`pulls HTTP ${prRes.status}`);
  const pr = await prRes.json();
  const headSha = pr.head?.sha;
  const cRes = await gh(`/repos/${REPO}/contents/${filePath}?ref=${headSha}`);
  if (!cRes.ok) return null;
  const c = await cRes.json();
  if (c.encoding !== "base64" || typeof c.content !== "string") return null;
  return JSON.parse(Buffer.from(c.content, "base64").toString("utf8"));
}

/** Fetch the changed files for a PR to locate the manifest path. */
async function fetchManifestPath(gh, prNumber) {
  const res = await gh(`/repos/${REPO}/pulls/${prNumber}/files?per_page=100`);
  if (!res.ok) throw new Error(`pulls/files HTTP ${res.status}`);
  const files = (await res.json()).map((f) => f.filename);
  return files.find((f) => /^io\.github\.[a-z0-9-]+\//.test(f)) ?? null;
}

/**
 * Path-traversal guard for tar entries (vendored from source.ts isSafePath).
 * Rejects absolute paths, `..` segments, and Windows drive letters.
 */
function isSafePath(entryPath) {
  const n = normalize(entryPath).replace(/\\/g, "/");
  if (n.startsWith("/")) return false;
  if (n.includes(":")) return false;
  if (n.includes("..")) return false;
  return !relative(".", n).startsWith("..");
}

/** Reject symlink/hardlink targets that escape the extract dir. */
function isSafeLinkTarget(extractDir, linkpath) {
  const n = normalize(linkpath).replace(/\\/g, "/");
  if (n.includes("..")) return false;
  return true;
}

/**
 * Download + extract the public source tarball with system curl + tar, then
 * validate the extracted tree rejects path traversal / symlink escapes. Returns
 * { extractDir, bundleDir, resolvedRef } — resolvedRef is the short SHA from the
 * top-dir name (RESEARCH §3.4 Option C), the D-06 snapshot evidence records.
 *
 * Exported so evidence-compute.mjs (Plan 04-04) reuses the same hardened clone.
 */
export async function cloneAndExtract(owner, repo, ref, sourcePath) {
  const extractDir = await mkdtemp(join(tmpdir(), "okfhub-clone-"));
  const tarballPath = join(extractDir, "source.tar.gz");

  // Download the public tarball with curl. -L follows the 302 → codeload redirect.
  // The GITHUB_TOKEN authorizes the api.github.com request (public repos are
  // anonymously readable, but the token is harmless and avoids rate limits).
  const tarballUrl = `${API}/repos/${owner}/${repo}/tarball/${ref}`;
  await execFileP("curl", [
    "-fsSL",
    "-H", `Authorization: token ${TOKEN}`,
    "-H", "Accept: application/vnd.github+json",
    "-o", tarballPath,
    tarballUrl,
  ]);

  // List entries BEFORE extracting, validate each is safe, then extract.
  const { stdout: listing } = await execFileP("tar", ["-tzf", tarballPath]);
  const entries = listing.split("\n").filter(Boolean);
  for (const entry of entries) {
    const pathOnly = entry.split(" -> ")[0];
    if (!isSafePath(pathOnly)) {
      throw new Error(`structure: refusing tarball entry escaping the extract dir: '${pathOnly}' (T-04-PATH).`);
    }
    // Reject any symlink/hardlink outright (OKF bundles are pure markdown trees).
    if (entry.includes(" -> ") || /^h\b|symlink/i.test(entry)) {
      const target = entry.split(" -> ")[1] ?? "";
      if (target && !isSafeLinkTarget(extractDir, target)) {
        throw new Error(`structure: refusing symlink/hardlink escaping the extract dir: '${entry}' (T-04-SYM).`);
      }
    }
  }

  // Extract (no-same-owner; system tar refuses unsafe paths by default on
  // ubuntu, but we validated above as defense-in-depth).
  await execFileP("tar", ["-xzf", tarballPath, "-C", extractDir, "--no-same-owner"]);
  await rm(tarballPath, { force: true });

  // The top-level dir is <owner>-<repo>-<shortsha>/ (RESEARCH §3.4 Option C).
  const entries2 = await readdir(extractDir, { withFileTypes: true });
  const topDir = entries2.find((e) => e.isDirectory() && /^.+-[0-9a-f]{6,40}$/i.test(e.name));
  if (!topDir) {
    throw new Error(`structure: downloaded tarball for ${owner}/${repo} had no recognized top-level dir (ref '${ref}').`);
  }
  const bundleDir = join(extractDir, topDir.name, sourcePath);
  try {
    await readdir(bundleDir);
  } catch {
    throw new Error(`structure: manifest source.path '${sourcePath}' not found in ${owner}/${repo} (ref '${ref}').`);
  }
  // The short SHA is the segment after the last '-' in the top-dir name
  // (RESEARCH §3.4 Option C — <owner>-<repo>-<shortsha>). D-06 resolved_sha.
  const resolvedRef = topDir.name.slice(topDir.name.lastIndexOf("-") + 1);
  return { extractDir, bundleDir, resolvedRef };
}

async function main() {
  if (!TOKEN) throw new Error("GITHUB_TOKEN not set — clone-source must run in the check half.");
  const event = await readEvent();
  const pr = event.pull_request;
  if (!pr) {
    console.log("clone-source: not a pull_request event — nothing to clone.");
    return;
  }

  const { gh } = makeGh(TOKEN);
  const manifestPath = await fetchManifestPath(gh, pr.number);
  if (!manifestPath) {
    console.log("clone-source: no io.github.* manifest in this PR — no source to clone (structure check skipped).");
    return;
  }

  const manifest = await fetchManifestAtHead(gh, pr.number, manifestPath);
  if (!manifest) {
    throw new Error(`clone-source: could not read manifest ${manifestPath} at the PR head.`);
  }
  if (!manifest.source || manifest.source.type !== "github") {
    throw new Error(`structure: source type '${manifest.source?.type}' is not supported (only 'github').`);
  }

  const { owner, repo } = parseGithubUrl(manifest.source.url);
  const ref = manifest.source.ref ?? "main";
  const sourcePath = manifest.source.path ?? "";

  const { extractDir, bundleDir } = await cloneAndExtract(owner, repo, ref, sourcePath);

  // Emit a machine-readable line: the bundleDir (consumed by the workflow) and
  // the extractDir (so the workflow can clean it up). Single-line JSON.
  console.log(JSON.stringify({ bundleDir, extractDir }));
}

// Run main() ONLY when this file is the entry point (node scripts/checks/clone-source.mjs),
// NOT when imported as a module (evidence-compute.mjs imports cloneAndExtract).
import { fileURLToPath as __fileURLToPath } from "node:url";
const __isMain = process.argv[1] && __fileURLToPath(import.meta.url) === __fileURLToPath(new URL(`file://${process.argv[1]}`));
if (__isMain) {
  main().catch(async (e) => {
    console.error(`clone-source failed: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  });
}
