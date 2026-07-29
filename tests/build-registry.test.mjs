// build-registry.test.mjs — aggregator evidence-compute tests (Phase 4, Option A).
//
// Tests the pure paths of computeEvidence() (extracted from build-registry.mjs
// for unit-testability): the non-github-source skip, and the source-clone
// failure path (graceful degradation to evidence-pending). The full clone +
// verifyBundle path makes a real network call and is exercised by the live
// build-registry.yml run (the e2e proof), not a unit test.
//
// Previously tested embedEvidence() (sidecar read); that design was replaced by
// inline compute after protected main rejected the App's sidecar push.
import { test } from "node:test";
import assert from "node:assert/strict";
import { computeEvidence } from "../scripts/build-registry.mjs";

/** A validated manifest object (ManifestSchema-shaped), github source. */
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

test("non-github source type → evidence skipped with warning, bundle stays evidence-pending", async () => {
  const manifest = {
    ...MANIFEST,
    source: { type: "tarball", url: "https://example.com/bundle.tar.gz", path: "", ref: "main" },
  };
  const { bundle, warning } = await computeEvidence(manifest, "io.github.google/ga4-ecommerce.json");
  assert.equal(bundle.evidence, undefined);
  assert.equal(bundle.name, "ga4-ecommerce"); // manifest fields preserved
  assert.match(warning, /source type 'tarball' not supported/);
});

test("unsupported source type carries the type name in the warning (no undefined leak)", async () => {
  const manifest = { ...MANIFEST, source: undefined };
  const { bundle, warning } = await computeEvidence(manifest, "io.github.google/ga4-ecommerce.json");
  assert.equal(bundle.evidence, undefined);
  assert.match(warning, /source type 'undefined' not supported/);
});

test("malformed source URL → clone fails gracefully, bundle stays evidence-pending", async () => {
  const manifest = {
    ...MANIFEST,
    source: { type: "github", url: "not-a-github-url", path: "", ref: "main" },
  };
  const { bundle, warning } = await computeEvidence(manifest, "io.github.google/ga4-ecommerce.json");
  assert.equal(bundle.evidence, undefined);
  assert.equal(bundle.name, "ga4-ecommerce");
  assert.match(warning, /evidence compute failed/);
  assert.match(warning, /not a recognized GitHub URL/);
});

test("a github source that 404s → bundle stays evidence-pending, warning names the failure", async () => {
  const manifest = {
    ...MANIFEST,
    source: { type: "github", url: "https://github.com/this-org-does-not-exist-xyz/nope", path: "", ref: "main" },
  };
  const { bundle, warning } = await computeEvidence(manifest, "io.github.google/ga4-ecommerce.json");
  assert.equal(bundle.evidence, undefined);
  assert.equal(bundle.name, "ga4-ecommerce");
  assert.match(warning, /evidence compute failed/);
});
