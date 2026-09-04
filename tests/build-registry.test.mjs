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

// ---------------------------------------------------------------------------
// Phase 8 (Plan 08-03 Task 1) — the computeEvidence http dispatch (HTTP-02).
//
// For source.type "http", computeEvidence dispatches to fetchHttpSource (injected
// via opts.fetchHttp for tests) → verifyBundle (UNCHANGED) → dnsVerify (opts.resolver)
// → computeReputation (with the dnsResult threaded in via opts.dnsResult). The
// resulting bundle carries `reputation` + `dns_verified_at` alongside evidence.
// A DNS verify failure degrades the bundle to dns-pending WITHOUT aborting the
// build (the per-bundle try/catch stays). verifyBundle runs identically for
// http and github (no semantic change).
//
// The opts.fetchHttp + opts.resolver + opts.dnsResult seams mirror the existing
// opts.clone + opts.gh injection pattern.
// ---------------------------------------------------------------------------

test("http source: computeEvidence dispatches fetchHttpSource + verifyBundle + dnsVerify + computeReputation(dns)", async () => {
  // 1) A local bundle dir with one valid concept so verifyBundle passes.
  const bundleDir = await mkdtemp(join(tmpdir(), "okfhub-http-ev-"));
  await mkdir(join(bundleDir, "concepts"), { recursive: true });
  await writeFile(join(bundleDir, "concepts", "orders.md"), "---\ntype: Table\n---\n\n# Orders\n", "utf8");

  const httpManifest = {
    schema_version: 1,
    name: "ga4-ecommerce",
    namespace: "io.http.example.com",
    description: "test",
    version: "1.0.0",
    source: { type: "http", url: "https://example.com/bundle.tar.gz", path: "", ref: "" },
    kind: "knowledge",
    categories: [],
  };

  // 2) opts.fetchHttp stub: returns the bundleDir as extractDir+bundleDir, with
  //    a content-SHA resolvedRef (mirrors the clone stub's {extractDir,bundleDir,resolvedRef}).
  const fetchHttp = async () => ({
    extractDir: bundleDir,
    bundleDir,
    resolvedRef: "a".repeat(64), // content SHA (64 hex)
  });

  // 3) opts.resolver stub: a matching TXT record so dnsVerify returns
  //    dns-verified-domain. The expected value is
  //    okfhub-verify=io.http.example.com/ga4-ecommerce (D-01).
  const expected = "okfhub-verify=io.http.example.com/ga4-ecommerce";
  const resolver = makeMockResolverForBuild({
    resolveTxt: () => [[expected]],
  });

  try {
    const { bundle, warning } = await computeEvidence(
      httpManifest,
      "io.http.example.com/ga4-ecommerce.json",
      { fetchHttp, resolver },
    );
    // verifyBundle ran (structural checks present) → evidence intact.
    assert.ok(bundle.evidence, "verifyBundle ran for the http source → evidence present");
    assert.equal(bundle.evidence.resolved_sha, "a".repeat(64), "resolvedRef = content SHA");
    assert.equal(bundle.source.resolved_sha, "a".repeat(64));
    // dnsVerify ran → dns_verified_at attached to the bundle.
    assert.ok(bundle.dns_verified_at, "dns_verified_at attached to the http bundle");
    assert.ok(typeof bundle.dns_verified_at === "string" && bundle.dns_verified_at.length > 0);
    // computeReputation http branch fired → dns-verified-domain reputation.
    assert.ok(bundle.reputation, "reputation populated for the http source");
    const dns = bundle.reputation.signals.find((s) => s.kind === "dns-verified-domain");
    assert.ok(dns, "dns-verified-domain reputation signal emitted");
    assert.equal(dns.value, "example.com");
    // NEVER verified-org for http (D-07).
    assert.equal(bundle.reputation.signals.find((s) => s.kind === "verified-org"), undefined);
  } finally {
    await rm(bundleDir, { recursive: true, force: true });
  }
});

test("http source: a DNS verify failure degrades to dns-pending WITHOUT aborting the build", async () => {
  const bundleDir = await mkdtemp(join(tmpdir(), "okfhub-http-fail-"));
  await mkdir(join(bundleDir, "concepts"), { recursive: true });
  await writeFile(join(bundleDir, "concepts", "orders.md"), "---\ntype: Table\n---\n\n# Orders\n", "utf8");

  const httpManifest = {
    schema_version: 1,
    name: "ga4-ecommerce",
    namespace: "io.http.example.com",
    description: "test",
    version: "1.0.0",
    source: { type: "http", url: "https://example.com/bundle.tar.gz", path: "", ref: "" },
    kind: "knowledge",
    categories: [],
  };

  const fetchHttp = async () => ({ extractDir: bundleDir, bundleDir, resolvedRef: "b".repeat(64) });

  // opts.resolver that returns NO TXT record → verifyDnsChallenge false →
  // no prior block → dns-pending. The build must NOT abort.
  const resolver = makeMockResolverForBuild({
    resolveTxt: () => [],
  });

  try {
    const { bundle, warning } = await computeEvidence(
      httpManifest,
      "io.http.example.com/ga4-ecommerce.json",
      { fetchHttp, resolver },
    );
    // Evidence still computed (DNS failure must not break it).
    assert.ok(bundle.evidence, "evidence intact despite the DNS failure");
    // Reputation degrades: dns-pending → reputation-pending (no verified-org).
    assert.ok(bundle.reputation, "reputation block present (dns-pending case)");
    const pending = bundle.reputation.signals.find((s) => s.kind === "reputation-pending");
    assert.ok(pending, "DNS failure degrades to reputation-pending");
    assert.equal(bundle.reputation.signals.find((s) => s.kind === "dns-verified-domain"), undefined);
    // No warning aborts the build (the per-bundle isolation stays).
    // A warning is acceptable (surfacing the DNS degradation to the log), but the
    // bundle is still returned with evidence + reputation.
    assert.equal(bundle.name, "ga4-ecommerce");
  } finally {
    await rm(bundleDir, { recursive: true, force: true });
  }
});

/** Build a mock resolver for the build-registry attachment test (mirrors the
 *  makeMockResolver factory in tests/checks/dns-verify.test.mjs). */
function makeMockResolverForBuild({ resolveNs, resolve4, resolveTxt } = {}) {
  const setServersCalls = [];
  return {
    setServersCalls,
    async resolveNs() {
      return resolveNs ?? ["ns1.example.com"];
    },
    async resolve4() {
      return resolve4 ?? ["1.2.3.4"];
    },
    setServers(servers) {
      setServersCalls.push(servers);
    },
    async resolveTxt() {
      if (typeof resolveTxt === "function") return resolveTxt();
      return resolveTxt ?? [];
    },
  };
}
