#!/usr/bin/env node
// Registry aggregator — validates every manifest, computes structural-conformance
// evidence INLINE, and writes a flat registry.json.
//
// Run:  npm ci && (cd scripts/checks && npm ci) && node scripts/build-registry.mjs
//
// Reads every `*.json` manifest under every `io.github.*/` namespace dir in
// this repo (io.github.google/, io.github.asagajda/, any io.github.<login>/),
// validates each against the vendored ManifestSchema, clones its source to run
// verifyBundle (the D-03 single source of truth), embeds the resulting evidence
// directly into the bundle object, and emits a flat
// `{ generated_at, count, bundles: Manifest[] }` at the repo root. The GitHub
// Action (.github/workflows/build-registry.yml) commits that file cross-repo
// into okfhub-website/public/registry.json.
//
// EVIDENCE INLINE (Phase 4, Option A — D-04 adapted): evidence is computed fresh
// on every build rather than read from git-tracked sidecars. The sidecar design
// was abandoned because protected `main` rejects the App's direct sidecar push
// (required_status_checks blocks direct pushes regardless of bypass — verified
// empirically with both classic protection GH006 and Rulesets GH013). Inline
// compute routes evidence through the already-working registry.json → website
// channel, touching no protected branch. Trade-off: evidence is no longer a
// standalone git-tracked sidecar, but it IS git-tracked inside registry.json
// (in the website repo) and is always freshly recomputed (T-09-TAMPER improved).
//
// On any validation error the script exits 1 with a list of the bad files — a
// publish-time guard so a malformed manifest can never reach the index.

import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
// Evidence pipeline (inline compute — Option A). verifyBundle is the D-03
// single source of truth; cloneAndExtract is the hardened source fetcher. Both
// live in scripts/checks/ and are imported here so the aggregator recomputes
// evidence fresh on every build (no git-tracked sidecar read).
import { verifyBundle } from "./checks/structure.mjs";
import { cloneAndExtract } from "./checks/clone-source.mjs";
import { sanitizeForComment } from "./checks/gate-lib.mjs";

// VENDORED from okfhub-cli/src/lib/manifest.ts — keep in sync (CLI is source of truth).
// Phase 1 of the manifest schema (ManifestSchema + SourceSchema). Byte-identical
// field list + constraints so the registry, the CLI, and the website all bind to
// one contract.

export const SourceType = z.enum(["github", "git", "tarball"]);

export const SourceSchema = z.object({
  type: SourceType,
  url: z.string().url(),
  path: z.string().default(""),
  ref: z.string().default("main"),
});

export const ManifestSchema = z.object({
  schema_version: z.literal(1),
  name: z.string().min(1),
  namespace: z.string().regex(/^io\.github\.[a-z0-9-]+$/),
  description: z.string(),
  version: z.string(),
  source: SourceSchema,
  kind: z.enum(["knowledge", "webapp"]).default("knowledge"),
  categories: z.array(z.string()).default([]),
  license: z.string().optional(),
  homepage: z.string().url().optional(),
});

// Scan EVERY io.github.* namespace directory, not just io.github.google. The
// D-20 fix updated the trigger's paths filter to `io.github.*/*.json` so
// external publishes (io.github.asagajda/, io.github.<any-login>/) fire the
// build — but if the aggregator only reads io.github.google/, external
// manifests trigger a build that then ignores them. Phase 3's self-publishing
// feature relies on this being consistent: trigger + discovery must cover the
// same set of namespaces.
const NAMESPACE_GLOB = "io.github.*";
const OUTPUT = "registry.json";

// Bump whenever a check's logic changes — recorded in each evidence object so a
// future consumer can tell whether two evidence snapshots are comparable.
const CHECK_LOGIC_VERSION = 1;

/**
 * Compute the D-10 evidence object for a manifest INLINE (Option A — no sidecar
 * read). Clones the public source, runs verifyBundle (5 checks), appends
 * source-reachable (the 6th — pass since the tarball GET succeeded), and returns
 * the manifest with `evidence` set + `source` resolved-sha metadata.
 *
 * Clones only PUBLIC source repos and runs verifyBundle which reads markdown
 * only — never eval/execs bundle files (T-06-PAWN). Every detail string is
 * sanitized (T-07-INJECT) since it can carry user-controlled bundle file paths.
 *
 * @param {object} manifest - the validated manifest (result.data)
 * @param {string} manifestPath - its repo-relative path (for warnings only)
 * @returns {Promise<{bundle: object, warning?: string}>} the manifest with
 *   `evidence` (the D-10 object) and `source` ({resolved_sha}) embedded, or the
 *   bare manifest with a warning if the source clone/verify failed (one bad
 *   bundle must never block the whole index — it stays evidence-pending).
 */
export async function computeEvidence(manifest, manifestPath) {
  if (!manifest.source || manifest.source.type !== "github") {
    return {
      bundle: { ...manifest },
      warning: `${manifestPath}: source type '${manifest.source?.type}' not supported (only 'github') — evidence skipped.`,
    };
  }
  try {
    const { owner, repo } = parseGithubUrl(manifest.source.url);
    const ref = manifest.source.ref ?? "main";
    const sourcePath = manifest.source.path ?? "";
    const { extractDir, bundleDir, resolvedRef } = await cloneAndExtract(owner, repo, ref, sourcePath);
    let checks;
    try {
      checks = (await verifyBundle(bundleDir)).checks;
    } finally {
      const { rm } = await import("node:fs/promises");
      await rm(extractDir, { recursive: true, force: true });
    }
    // The 6th check (source-reachable) — pass since the tarball GET succeeded.
    checks.push({ id: "source-reachable", name: "Source repo reachable", severity: "quality", status: "pass" });
    return {
      bundle: {
        ...manifest,
        evidence: {
          evidence_version: 1,
          namespace: manifest.namespace,
          name: manifest.name,
          resolved_sha: resolvedRef,
          checked_at: new Date().toISOString(),
          check_logic_version: CHECK_LOGIC_VERSION,
          checks: sanitizeChecks(checks),
        },
        source: { resolved_sha: resolvedRef },
      },
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      bundle: { ...manifest },
      warning: `${manifestPath}: evidence compute failed (${msg}) — bundle stays evidence-pending.`,
    };
  }
}

/** Parse owner/repo from a github source URL (mirrors source.ts parseGithubUrl). */
function parseGithubUrl(url) {
  const m = /^https:\/\/github\.com\/([^/]+)\/([^/?#]+?)(?:\.git)?(?:[/?#]|$)/.exec(url);
  if (!m) throw new Error(`source.url '${url}' is not a recognized GitHub URL.`);
  return { owner: m[1], repo: m[2] };
}

/** Sanitize every detail string in a checks array (T-07-INJECT). */
function sanitizeChecks(checks) {
  return checks.map((c) =>
    c.detail !== undefined ? { ...c, detail: sanitizeForComment(c.detail) } : { ...c },
  );
}

async function collectManifests() {
  const top = await readdir(".", { withFileTypes: true });
  const namespaceDirs = top
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .filter((name) => {
      // Match io.github.<lowercase-identifier> — the namespace pattern the
      // manifest schema enforces (manifest.namespace regex).
      return /^io\.github\.[a-z0-9-]+$/.test(name);
    })
    .sort();
  const allFiles = [];
  for (const dir of namespaceDirs) {
    const entries = await readdir(dir, { recursive: true, withFileTypes: false });
    const files = entries
      .filter((f) => typeof f === "string" && f.endsWith(".json"))
      .map((f) => join(dir, f));
    allFiles.push(...files);
  }
  return allFiles.sort();
}

async function main() {
  const files = await collectManifests();
  const bundles = [];
  const errors = [];

  for (const rel of files) {
    let text;
    try {
      text = await readFile(rel, "utf8");
    } catch (e) {
      errors.push(`${rel}: could not read (${e instanceof Error ? e.message : String(e)})`);
      continue;
    }
    let json;
    try {
      json = JSON.parse(text);
    } catch (e) {
      errors.push(`${rel}: invalid JSON (${e instanceof Error ? e.message : String(e)})`);
      continue;
    }
    const result = ManifestSchema.safeParse(json);
    if (!result.success) {
      const issues = result.error.issues
        .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
        .join("; ");
      errors.push(`${rel}: ${issues}`);
      continue;
    }
    // D-04 (Phase 4, Option A — inline compute): clone the source, run
    // verifyBundle, and embed the fresh evidence object directly into the bundle.
    // A clone/verify failure is non-fatal — the bundle stays evidence-pending
    // (the website degrades to "pending" per Plan 04-02), but the index still ships.
    const { bundle: bundleObj, warning } = await computeEvidence(result.data, rel);
    if (warning) console.warn(`⚠️ evidence: ${warning}`);
    bundles.push({ ...bundleObj, __path: rel });
  }

  if (errors.length > 0) {
    console.error("❌ manifest validation failed:\n" + errors.join("\n"));
    process.exit(1);
  }

  // Defense-in-depth (audit finding): reject duplicate namespace+name entries.
  // The merge-gate now enforces namespace-field===path, but build-registry is
  // the LAST gate before the index ships — a duplicate here would mean two
  // files resolve to the same slug in registry.json (index pollution /
  // install ambiguity). Fail closed: if two manifests declare the same
  // namespace+name, the build fails rather than emitting a broken index.
  // Also cross-check that each manifest's declared namespace matches its
  // directory path (belt-and-braces alongside the gate's check).
  const seen = new Map(); // `${namespace}/${name}` → path
  for (const b of bundles) {
    const key = `${b.namespace}/${b.name}`;
    // namespace-field/path consistency (the path dir must equal the namespace).
    const pathOrg = b.__path.match(/^io\.github\.([a-z0-9-]+)\//)?.[1];
    if (pathOrg && pathOrg !== b.namespace.replace(/^io\.github\./, "")) {
      errors.push(`${b.__path}: namespace field '${b.namespace}' does not match its directory '${pathOrg}' (namespace/path mismatch).`);
      continue;
    }
    if (seen.has(key)) {
      errors.push(`${b.__path}: duplicate slug '${key}' (already declared at ${seen.get(key)}). Each namespace+name must be unique.`);
      continue;
    }
    seen.set(key, b.__path);
  }
  // Strip the internal __path marker before emitting.
  for (const b of bundles) delete b.__path;

  if (errors.length > 0) {
    console.error("❌ registry integrity check failed:\n" + errors.join("\n"));
    process.exit(1);
  }

  // Stable ordering: by namespace then name, so the generated registry.json has
  // a deterministic diff between runs regardless of readdir order.
  bundles.sort((a, b) =>
    `${a.namespace}/${a.name}`.localeCompare(`${b.namespace}/${b.name}`),
  );

  const output = {
    generated_at: new Date().toISOString(),
    count: bundles.length,
    bundles,
  };

  await writeFile(OUTPUT, JSON.stringify(output, null, 2) + "\n", "utf8");
  console.log(`✅ aggregated ${bundles.length} bundles → ${OUTPUT}`);
}

// Run main() ONLY when this file is the entry point, not when imported (tests
// import embedEvidence directly).
import { fileURLToPath as __fileURLToPath } from "node:url";
const __isMain = process.argv[1] && __fileURLToPath(import.meta.url) === __fileURLToPath(new URL(`file://${process.argv[1]}`));
if (__isMain) {
  main().catch((e) => {
    console.error(`❌ build-registry failed: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  });
}
