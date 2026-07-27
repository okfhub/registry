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
    bundles.push(result.data);
  }

  if (errors.length > 0) {
    console.error("❌ manifest validation failed:\n" + errors.join("\n"));
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

main().catch((e) => {
  console.error(`❌ build-registry failed: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
