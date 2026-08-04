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
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
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

// ---------------------------------------------------------------------------
// Phase 7 (Plan 07-01 Task 2) — the computeEvidence → computeReputation attachment test.
//
// All 4 pre-existing tests above early-return/throw BEFORE the reputation call
// site at build-registry.mjs (tests 1-2 non-github early-return; test 3
// parseGithubUrl throw; test 4 clone throw), so none certify that `reputation`
// actually attaches to the returned bundle. This test injects BOTH seams:
//   - opts.clone (a local-dir stub returning a valid bundleDir — the existing
//     idiom at build-registry.mjs L145 — so verifyBundle + materializeConcepts
//     succeed without a network clone)
//   - opts.gh (the new reputation fetcher seam — a stub mapping /repos → 200,
//     /users → Organization, /orgs → is_verified:true)
// and asserts bundle.reputation is populated: verified-org + host-popularity
// signals + a valid ISO-8601 checked_at. This is the dynamic proof that
// computeEvidence → computeReputation fires (the must_haves.key_links claim).
// ---------------------------------------------------------------------------

/** Build a mock Response (mirrors reputation.test.mjs). */
function mockResponse(status, body, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (n) => headers[n.toLowerCase()] ?? headers[n] ?? null },
    async json() { return body; },
  };
}

test("computeEvidence attaches reputation to the bundle (opts.clone + opts.gh injected, D-02)", async () => {
  // 1) A local bundle dir with one valid concept so verifyBundle passes.
  const bundleDir = await mkdtemp(join(tmpdir(), "okfhub-rep-"));
  await mkdir(join(bundleDir, "concepts"), { recursive: true });
  await writeFile(join(bundleDir, "concepts", "orders.md"), "---\ntype: Table\n---\n\n# Orders\n", "utf8");

  // 2) opts.clone stub: returns a bundleDir pointing at the temp fixture (no
  //    network clone). resolvedRef is a dummy 40-char SHA.
  const clone = async () => ({
    extractDir: bundleDir,
    bundleDir,
    resolvedRef: "a".repeat(40),
  });

  // 3) opts.gh stub: the reputation fetcher returns /repos 200 (stars/forks),
  //    /users Organization, /orgs is_verified:true → verified-org + host-popularity.
  const gh = async (path) => {
    if (path.startsWith("/repos/")) return mockResponse(200, { stargazers_count: 42, forks_count: 7 });
    if (path.startsWith("/users/")) return mockResponse(200, { type: "Organization" });
    if (path.startsWith("/orgs/")) return mockResponse(200, { is_verified: true });
    throw new Error(`mock gh: unexpected path ${path}`);
  };

  try {
    const { bundle, warning } = await computeEvidence(MANIFEST, "io.github.google/ga4-ecommerce.json", { clone, gh });
    // Evidence still computed (the reputation hook must not break it).
    assert.equal(warning, undefined, "no warning — the success path");
    assert.ok(bundle.evidence, "evidence intact alongside reputation");

    // THE load-bearing assertion: reputation is populated on the returned bundle.
    assert.ok(bundle.reputation, "bundle.reputation is populated (D-02 attachment fires)");
    const rep = bundle.reputation;
    assert.equal(rep.reputation_version, 1);
    assert.equal(rep.source_type, "github");
    assert.ok(typeof rep.reputation_logic_version === "number");

    // checked_at parses as a valid ISO-8601 Date.
    const checkedAt = new Date(rep.checked_at);
    assert.ok(!Number.isNaN(checkedAt.getTime()), `checked_at is valid ISO-8601: ${rep.checked_at}`);

    // verified-org signal present with value true.
    const vo = rep.signals.find((s) => s.kind === "verified-org");
    assert.ok(vo, "verified-org signal present");
    assert.equal(vo.value, true);

    // host-popularity signal present with stars/forks from the mocked /repos.
    const pop = rep.signals.find((s) => s.kind === "host-popularity");
    assert.ok(pop, "host-popularity signal present");
    assert.deepEqual(pop.value, { stars: 42, forks: 7 });
  } finally {
    await rm(bundleDir, { recursive: true, force: true });
  }
});
