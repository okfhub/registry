#!/usr/bin/env node
// Registry aggregator — validates every manifest and writes a flat registry.json.
//
// Run:  npm ci && node scripts/build-registry.mjs
//
// Reads every `*.json` manifest under every `io.github.*/` namespace dir in
// this repo (io.github.google/, io.github.asagajda/, any io.github.<login>/),
// validates each against the vendored ManifestSchema, and
// emits a flat `{ generated_at, count, bundles: Manifest[] }` at the repo root.
// The GitHub Action (.github/workflows/build-registry.yml) commits that file
// cross-repo into okfhub-website/public/registry.json.
//
// On any validation error the script exits 1 with a list of the bad files — a
// publish-time guard so a malformed manifest can never reach the index.

import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";

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

/** Collect every `*.json` under all io.github.* namespace dirs, sorted for
 *  stable output. Reads the top-level entries, filters to dirs matching the
 *  namespace glob, then recursively collects manifests from each. */
/**
 * Embed a sidecar's evidence into a validated manifest (D-04). Pure + testable.
 *
 * Looks for `io.github.<org>/<name>.evidence.json` beside the manifest. If the
 * sidecar exists, cross-checks its namespace+name against the manifest's
 * (T-08-MISMATCH — fail-closed), then returns the manifest with `evidence` set.
 * If absent, returns the manifest unchanged (the website degrades to "pending"
 * per Plan 04-02). A malformed sidecar (bad JSON / missing fields) is skipped
 * with a warning rather than failing the whole build — one bad sidecar must not
 * block the index.
 *
 * @param {object} manifest - the validated manifest (result.data)
 * @param {string} manifestPath - its repo-relative path (for locating the sidecar + errors)
 * @param {(p: string) => Promise<string|undefined>} [readFileFn] - injectable read (tests)
 * @returns {Promise<{bundle: object, warning?: string, mismatch?: true}>}
 */
export async function embedEvidence(manifest, manifestPath, readFileFn = safeReadFile) {
  const sidecarPath = manifestPath.replace(/\.json$/, ".evidence.json");
  const sidecarText = await readFileFn(sidecarPath);
  if (sidecarText === undefined) {
    // No sidecar — backward-compatible: emit the manifest with no evidence field.
    return { bundle: { ...manifest } };
  }
  let sidecar;
  try {
    sidecar = JSON.parse(sidecarText);
  } catch {
    return {
      bundle: { ...manifest },
      warning: `${sidecarPath}: malformed JSON — skipped (bundle stays evidence-pending).`,
    };
  }
  // T-08-MISMATCH: a sidecar placed at the wrong path (namespace impersonation)
  // fails closed. The aggregator never silently embeds cross-namespace evidence.
  if (
    typeof sidecar.namespace !== "string" ||
    typeof sidecar.name !== "string" ||
    sidecar.namespace !== manifest.namespace ||
    sidecar.name !== manifest.name
  ) {
    return {
      bundle: { ...manifest },
      mismatch: true,
      warning: `${sidecarPath}: namespace/name mismatch (sidecar ${sidecar.namespace}/${sidecar.name} vs manifest ${manifest.namespace}/${manifest.name}) — NOT embedded.`,
    };
  }
  return { bundle: { ...manifest, evidence: sidecar } };
}

/** Read a file, returning undefined if it does not exist (non-fatal absence). */
async function safeReadFile(p) {
  const { readFile } = await import("node:fs/promises");
  try {
    return await readFile(p, "utf8");
  } catch {
    return undefined;
  }
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
    // D-04 (Phase 4): embed the evidence sidecar beside this manifest, if any.
    // A missing sidecar is non-fatal (backward-compatible); a namespace mismatch
    // or malformed sidecar emits a warning but keeps the bundle (evidence-pending).
    const { bundle: bundleObj, warning } = await embedEvidence(result.data, rel);
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
