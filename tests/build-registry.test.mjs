// build-registry.test.mjs — aggregator evidence-embedding tests (Phase 4, D-04).
//
// Tests the pure embedEvidence() function (extracted from build-registry.mjs for
// unit-testability). Covers: matching sidecar embeds; missing sidecar degrades
// to evidence-pending (backward-compatible); namespace/name mismatch fails
// closed (T-08-MISMATCH); malformed sidecar is skipped with a warning.
import { test } from "node:test";
import assert from "node:assert/strict";
import { embedEvidence } from "../scripts/build-registry.mjs";

/** A validated manifest object (ManifestSchema-shaped). */
const MANIFEST = {
  schema_version: 1,
  name: "ga4-ecommerce",
  namespace: "io.github.google",
  description: "test",
  version: "1.0.0",
  source: { type: "github", url: "https://github.com/GoogleCloudPlatform/kc", path: "", ref: "main" },
  kind: "knowledge",
  categories: [],
};

/** A valid D-10 sidecar matching MANIFEST's namespace/name. */
const SIDECAR = {
  evidence_version: 1,
  namespace: "io.github.google",
  name: "ga4-ecommerce",
  resolved_sha: "d44368c15e38e7c92481c5992e4f9b5b421a801d",
  checked_at: "2026-07-29T00:00:00Z",
  check_logic_version: 1,
  checks: [
    { id: "bundle-root", name: "Bundle root exists", severity: "identity", status: "pass" },
    { id: "source-reachable", name: "Source repo reachable", severity: "quality", status: "pass" },
  ],
};

test("manifest WITH matching-namespace sidecar → bundle has .evidence", async () => {
  const sidecarText = JSON.stringify(SIDECAR);
  const readFileFn = async (p) =>
    p === "io.github.google/ga4-ecommerce.evidence.json" ? sidecarText : undefined;
  const { bundle } = await embedEvidence(MANIFEST, "io.github.google/ga4-ecommerce.json", readFileFn);
  // embedEvidence parses the sidecar text, so compare structurally (not by ref).
  assert.deepEqual(bundle.evidence, JSON.parse(sidecarText));
  assert.equal(bundle.name, "ga4-ecommerce"); // manifest fields preserved
});

test("manifest WITHOUT a sidecar → bundle has no evidence field (backward-compatible)", async () => {
  const readFileFn = async () => undefined; // no sidecar exists
  const { bundle } = await embedEvidence(MANIFEST, "io.github.google/ga4-ecommerce.json", readFileFn);
  assert.equal(bundle.evidence, undefined);
  assert.equal(bundle.name, "ga4-ecommerce");
});

test("sidecar namespace mismatch → NOT embedded (T-08-MISMATCH), bundle stays evidence-pending", async () => {
  const mismatched = { ...SIDECAR, namespace: "io.github.evil", name: "impersonator" };
  const readFileFn = async () => JSON.stringify(mismatched);
  const { bundle, mismatch, warning } = await embedEvidence(
    MANIFEST,
    "io.github.google/ga4-ecommerce.json",
    readFileFn,
  );
  assert.equal(mismatch, true);
  assert.equal(bundle.evidence, undefined); // fail-closed: not embedded
  assert.match(warning, /namespace\/name mismatch/);
});

test("malformed sidecar (bad JSON) → skipped with a warning, bundle stays evidence-pending", async () => {
  const readFileFn = async () => "{ not valid json";
  const { bundle, warning } = await embedEvidence(
    MANIFEST,
    "io.github.google/ga4-ecommerce.json",
    readFileFn,
  );
  assert.equal(bundle.evidence, undefined);
  assert.match(warning, /malformed JSON/);
});

test("sidecar with missing namespace field → treated as mismatch (fail-closed)", async () => {
  const partial = { evidence_version: 1, checked_at: "2026-07-29T00:00:00Z", checks: [] };
  const readFileFn = async () => JSON.stringify(partial);
  const { bundle, mismatch } = await embedEvidence(
    MANIFEST,
    "io.github.google/ga4-ecommerce.json",
    readFileFn,
  );
  assert.equal(mismatch, true);
  assert.equal(bundle.evidence, undefined);
});
