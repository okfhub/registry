#!/usr/bin/env node
// Registry aggregator — validates every manifest and writes a flat registry.json.
//
// Run:  npm ci && node scripts/build-registry.mjs
//
// Reads every `*.json` manifest under `io.github.google/` (the real namespace
// layout of this repo), validates each against the vendored ManifestSchema, and
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

const MANIFESTS_DIR = "io.github.google";
const OUTPUT = "registry.json";

/** Recursively collect every `*.json` under the namespace dir, sorted for stable output. */
async function collectManifests(dir) {
  const entries = await readdir(dir, { recursive: true, withFileTypes: false });
  const files = entries
    .filter((f) => typeof f === "string" && f.endsWith(".json"))
    .map((f) => join(dir, f))
    .sort();
  return files;
}

async function main() {
  const files = await collectManifests(MANIFESTS_DIR);
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
