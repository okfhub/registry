// schema.mjs — manifest schema check for the merge-gate (Phase 3, AUTH-03 / D-04).
//
// VENDORED from okfhub-cli/src/lib/manifest.ts (L52-65) — byte-identical field
// list + constraints. The CLI is the source of truth; this copy lives in the
// registry-repo (a separate package) so the merge-gate validates publish PRs
// against the exact contract the CLI publishes + the website reads. Keep in
// sync with okfhub-cli/src/lib/manifest.ts AND scripts/build-registry.mjs.
//
// AUTH-03 (v1): namespaces constrained to io.github.* only, enforced by the
// namespace regex. Phase 8 widens to io.(github|http).<segment> — the http
// family allows dots+hyphens because the segment is a domain. The merge-gate
// runs this BEFORE ownership/path-scope so a non-conforming manifest is
// rejected at schema parse.

import { z } from "zod";

export const SourceType = z.enum(["github", "git", "tarball", "http"]);

export const SourceSchema = z.object({
  type: SourceType,
  url: z.string().url(),
  path: z.string().default(""),
  ref: z.string().default("main"),
});

// paid-01 — the paid-layer block. VENDORED mirror of okfhub-cli
// src/lib/manifest.ts PaidSchema (the coordinated 4-copy rule: CLI manifest.ts,
// THIS file, okfhub-website/lib/types.ts, and the registry index shape).
// Whole-bundle model: a paid bundle's `source` IS the private content repo —
// the paid block carries only the monetization metadata. Publisher-set pricing
// only: okfhub never sets, caps, or intermediates prices; price_hint is
// display-only (verified by review against the live Polar page).
export const PaidSchema = z.object({
  provider: z.literal("polar"),
  organization_id: z.string().min(1),
  product_id: z.string().min(1),
  benefit_id: z.string().min(1),
  checkout_url: z.string().url(),
  price_hint: z.object({
    amount: z.number().nonnegative(),
    currency: z.string().regex(/^[a-zA-Z]{3}$/),
    recurring: z.enum(["day", "week", "month", "year"]).nullish(),
  }),
  includes: z.array(z.string().min(1)).default([]),
});

export const ManifestSchema = z.object({
  schema_version: z.literal(1),
  // WR-07: constrain name to lowercase-kebab (matches the namespace shape) so a
  // manifest name with traversal chars (e.g. "../../x") cannot write outside
  // concepts/ during materialization. Keep in sync with build-registry.mjs + CLI.
  name: z.string().regex(/^[a-z0-9-]+$/, "name must be lowercase-kebab (a-z, 0-9, -) only"),
  namespace: z.string().regex(/^io\.(github|http)\.[a-z0-9.-]+$/),
  description: z.string(),
  version: z.string(),
  source: SourceSchema,
  kind: z.enum(["knowledge", "webapp"]).default("knowledge"),
  categories: z.array(z.string()).default([]),
  license: z.string().optional(),
  homepage: z.string().url().optional(),
  // paid-01 — additive + optional; absent on free-only bundles.
  paid: PaidSchema.optional(),
});

/**
 * Validate a parsed manifest JSON object against ManifestSchema.
 *
 * @param {unknown} manifestJson
 * @returns {{passed: boolean, reason: string}}
 */
export function checkSchema(manifestJson) {
  const result = ManifestSchema.safeParse(manifestJson);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
      .join("; ");
    return {
      passed: false,
      reason: `schema: manifest failed validation — ${issues}`,
    };
  }
  return { passed: true, reason: "schema: manifest valid." };
}
