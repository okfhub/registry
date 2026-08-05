// reputation.test.mjs — publisher reputation compute tests (Phase 7, Plan 07-01).
//
// Mirrors build-registry.test.mjs's node --test imports + MANIFEST fixture +
// graceful-degradation assertions. The load-bearing seam is opts.gh — a mocked
// fetcher returning canned Response objects (mirrors computeEvidence's opts.clone
// override at build-registry.mjs:145) so every REST call is mockable without
// network. Covers REP-01/02/03/04, D-06/D-07, and the 07-VALIDATION.md Critical
// Edges backstop (items 1-8).
import { test } from "node:test";
import assert from "node:assert/strict";
import { computeReputation } from "../../scripts/checks/reputation.mjs";

/** A validated manifest object (github source), mirroring build-registry.test.mjs. */
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

/** Build a mock Response object with .ok, .status, .headers.get, async .json().
 *  Mirrors the shape makeGh()'s gh() returns (a fetch Response). */
function mockResponse(status, body, headers = {}) {
  const ok = status >= 200 && status < 300;
  return {
    ok,
    status,
    headers: {
      get(name) {
        // Case-insensitive lookup against the provided headers (for rate-limit).
        const key = Object.keys(headers).find(
          (k) => k.toLowerCase() === name.toLowerCase(),
        );
        return key ? headers[key] : null;
      },
    },
    async json() {
      return body;
    },
  };
}

/** Build a mock gh(path) fetcher that maps path → mock Response. Default
 *  fallbacks cover the common endpoints so individual tests only override
 *  the response they care about. */
function makeMockGh(responses) {
  return async function gh(path) {
    if (path in responses) {
      const r = responses[path];
      return typeof r === "function" ? r() : r;
    }
    throw new Error(`mock gh: unexpected path ${path}`);
  };
}

/** Find a signal of a given kind in a signals[] array (undefined if absent). */
function findSignal(reputation, kind) {
  return reputation?.signals?.find((s) => s.kind === kind);
}

test("org-owner (/users Organization + /orgs is_verified) → verified-org + host-popularity signals", async () => {
  const gh = makeMockGh({
    "/repos/GoogleCloudPlatform/kc": mockResponse(200, { stargazers_count: 42, forks_count: 7 }),
    "/users/GoogleCloudPlatform": mockResponse(200, { type: "Organization" }),
    "/orgs/GoogleCloudPlatform": mockResponse(200, { is_verified: true }),
  });
  const { reputation, warning } = await computeReputation(MANIFEST, undefined, { gh });
  assert.equal(warning, undefined, "no warning on success");
  assert.ok(reputation, "reputation block present");
  const vo = findSignal(reputation, "verified-org");
  assert.ok(vo, "verified-org signal present");
  assert.equal(vo.value, true);
  const pop = findSignal(reputation, "host-popularity");
  assert.ok(pop, "host-popularity signal present");
  assert.deepEqual(pop.value, { stars: 42, forks: 7 });
  // Envelope fields
  assert.equal(reputation.reputation_version, 1);
  assert.equal(reputation.source_type, "github");
  assert.equal(reputation.reputation_logic_version, 1);
  assert.ok(typeof reputation.checked_at === "string" && reputation.checked_at.length > 0);
});

test("user-owner (/users type User) → host-popularity present, verified-org ABSENT (no /orgs call)", async () => {
  const calls = [];
  const gh = async (path) => {
    calls.push(path);
    if (path === "/repos/GoogleCloudPlatform/kc") return mockResponse(200, { stargazers_count: 5, forks_count: 1 });
    if (path === "/users/GoogleCloudPlatform") return mockResponse(200, { type: "User" });
    throw new Error(`mock gh: unexpected path ${path}`);
  };
  const { reputation } = await computeReputation(MANIFEST, undefined, { gh });
  assert.ok(findSignal(reputation, "host-popularity"), "host-popularity present for user-owner");
  assert.equal(findSignal(reputation, "verified-org"), undefined, "no verified-org for user-owner");
  // /orgs must NOT be called for a User owner (research A4 — skip the call).
  assert.ok(!calls.some((p) => p.startsWith("/orgs/")), "/orgs not called for User owner");
});

test("/repos 200 → stars/forks come from stargazers_count/forks_count fields (not watchers)", async () => {
  // The mock feeds the real GitHub field names. computeReputation must read
  // stargazers_count + forks_count (NOT watchers_count — the legacy alias).
  const gh = makeMockGh({
    "/repos/GoogleCloudPlatform/kc": mockResponse(200, { stargazers_count: 1234, forks_count: 56 }),
    "/users/GoogleCloudPlatform": mockResponse(200, { type: "Organization" }),
    "/orgs/GoogleCloudPlatform": mockResponse(200, { is_verified: false }),
  });
  const { reputation } = await computeReputation(MANIFEST, undefined, { gh });
  const pop = findSignal(reputation, "host-popularity");
  assert.deepEqual(pop.value, { stars: 1234, forks: 56 });
});

test("/repos 404 → single repo-unreachable signal, NO host-popularity, NO stale stars (D-07, A-SUB)", async () => {
  const gh = makeMockGh({
    "/repos/GoogleCloudPlatform/kc": mockResponse(404, { message: "Not Found" }),
  });
  const { reputation, warning } = await computeReputation(MANIFEST, undefined, { gh });
  // A-SUB: the block IS persisted WITH the sticky signal (not omitted).
  assert.ok(reputation, "reputation block present for sticky 404 (A-SUB)");
  assert.equal(warning, undefined, "sticky 404 is not a warning/pending state");
  assert.equal(findSignal(reputation, "host-popularity"), undefined, "NO host-popularity on 404");
  const unreachable = findSignal(reputation, "repo-unreachable");
  assert.ok(unreachable, "repo-unreachable signal present");
  assert.equal(unreachable.detail !== undefined, true);
  // No stale stars carried (Pitfall 2.4).
  assert.equal(findSignal(reputation, "verified-org"), undefined, "no verified-org on 404");
});

test("/repos 429 → transient → reputation undefined + warning (pending, A-CF/A-OMIT)", async () => {
  const gh = makeMockGh({
    "/repos/GoogleCloudPlatform/kc": mockResponse(429, { message: "rate limited" }, { "x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999" }),
  });
  const { reputation, warning } = await computeReputation(MANIFEST, undefined, { gh });
  assert.equal(reputation, undefined, "transient → reputation undefined (pending, A-OMIT)");
  assert.ok(warning, "warning present for transient failure");
  assert.match(warning, /transient/);
});

test("priorReputation checked_at 23h59m ago + 429 → carry-forward returns prior block (ORIGINAL checked_at)", async () => {
  const justUnder = new Date(Date.now() - (23 * 60 * 60 * 1000 + 59 * 60 * 1000)).toISOString();
  const prior = {
    reputation_version: 1,
    source_type: "github",
    checked_at: justUnder,
    reputation_logic_version: 1,
    signals: [{ kind: "host-popularity", value: { stars: 99, forks: 3 }, detail: "popularity ≠ safety" }],
  };
  const gh = makeMockGh({
    "/repos/GoogleCloudPlatform/kc": mockResponse(429, { message: "rate limited" }),
  });
  const { reputation, warning } = await computeReputation(MANIFEST, prior, { gh });
  assert.ok(reputation, "carry-forward returns the prior block");
  assert.equal(reputation.checked_at, justUnder, "ORIGINAL checked_at preserved (not refreshed)");
  assert.equal(warning, undefined, "carry-forward is not a warning/pending state");
  assert.deepEqual(findSignal(reputation, "host-popularity").value, { stars: 99, forks: 3 });
});

test("priorReputation checked_at 24h01m ago + 429 → pending (reputation undefined)", async () => {
  const justOver = new Date(Date.now() - (24 * 60 * 60 * 1000 + 60 * 1000)).toISOString();
  const prior = {
    reputation_version: 1,
    source_type: "github",
    checked_at: justOver,
    reputation_logic_version: 1,
    signals: [{ kind: "host-popularity", value: { stars: 99, forks: 3 }, detail: "popularity ≠ safety" }],
  };
  const gh = makeMockGh({
    "/repos/GoogleCloudPlatform/kc": mockResponse(429, { message: "rate limited" }),
  });
  const { reputation, warning } = await computeReputation(MANIFEST, prior, { gh });
  assert.equal(reputation, undefined, "prior > 24h → pending (not carried forward)");
  assert.ok(warning, "warning present for pending");
});

test("org name with HTML chars in detail is backslash-escaped by sanitizeForComment (no raw <script>)", async () => {
  // A hostile source.url whose owner segment contains HTML injection chars.
  // parseGithubUrl accepts the owner segment (its regex [^/]+ matches HTML
  // chars); the org name flows into the verified-org detail and MUST be
  // backslash-escaped (T-07-INJECT).
  //
  // The owner `evil<img>` parses cleanly (no internal slash). The org name
  // lands in the verified-org detail string, which sanitizeForComment escapes.
  const hostileManifest = {
    ...MANIFEST,
    namespace: "io.github.evilorg",
    source: { type: "github", url: "https://github.com/evil<img>/kc", path: "", ref: "main" },
  };
  const gh = makeMockGh({
    "/repos/evil<img>/kc": mockResponse(200, { stargazers_count: 0, forks_count: 0 }),
    "/users/evil<img>": mockResponse(200, { type: "Organization" }),
    "/orgs/evil<img>": mockResponse(200, { is_verified: true }),
  });
  const { reputation } = await computeReputation(hostileManifest, undefined, { gh });
  const vo = findSignal(reputation, "verified-org");
  assert.ok(vo, "verified-org signal present");
  // The detail must NOT contain a raw <img> — it must be backslash-escaped.
  assert.ok(!vo.detail.includes("<img>"), "no raw <img> in detail");
  assert.ok(vo.detail.includes("\\<"), "detail backslash-escapes the HTML char");
});

test("non-github source type → reputation undefined + warning naming the unsupported type", async () => {
  const manifest = {
    ...MANIFEST,
    source: { type: "tarball", url: "https://example.com/bundle.tar.gz", path: "", ref: "main" },
  };
  const { reputation, warning } = await computeReputation(manifest, undefined, {});
  assert.equal(reputation, undefined);
  assert.ok(warning);
  assert.match(warning, /source type 'tarball' not supported/);
});

test("zero stars + zero forks → host-popularity value {stars:0, forks:0} (normal, not negative — Pitfall 2.3)", async () => {
  const gh = makeMockGh({
    "/repos/GoogleCloudPlatform/kc": mockResponse(200, { stargazers_count: 0, forks_count: 0 }),
    "/users/GoogleCloudPlatform": mockResponse(200, { type: "User" }),
  });
  const { reputation } = await computeReputation(MANIFEST, undefined, { gh });
  const pop = findSignal(reputation, "host-popularity");
  assert.deepEqual(pop.value, { stars: 0, forks: 0 });
});

test("/orgs 404 for an org owner is NOT a transient error (no verified-org, host-popularity intact)", async () => {
  // Edge 2: /orgs 404 (org lost verification OR owner is a user misread as org
  // by /users) must not abort the block — host-popularity still ships.
  const gh = makeMockGh({
    "/repos/GoogleCloudPlatform/kc": mockResponse(200, { stargazers_count: 10, forks_count: 2 }),
    "/users/GoogleCloudPlatform": mockResponse(200, { type: "Organization" }),
    "/orgs/GoogleCloudPlatform": mockResponse(404, { message: "Not Found" }),
  });
  const { reputation, warning } = await computeReputation(MANIFEST, undefined, { gh });
  assert.ok(reputation, "block present (orgs 404 is not transient)");
  assert.equal(warning, undefined);
  assert.equal(findSignal(reputation, "verified-org"), undefined, "no verified-org on /orgs 404");
  assert.ok(findSignal(reputation, "host-popularity"), "host-popularity intact despite /orgs 404");
});

test("/repos 5xx → transient → pending (reputation undefined + warning)", async () => {
  const gh = makeMockGh({
    "/repos/GoogleCloudPlatform/kc": mockResponse(503, { message: "Service Unavailable" }),
  });
  const { reputation, warning } = await computeReputation(MANIFEST, undefined, { gh });
  assert.equal(reputation, undefined);
  assert.ok(warning);
  assert.match(warning, /transient/);
});

test("network error on /repos → transient → pending", async () => {
  const gh = async () => {
    throw new Error("EAI_AGAIN dns lookup failed");
  };
  const { reputation, warning } = await computeReputation(MANIFEST, undefined, { gh });
  assert.equal(reputation, undefined);
  assert.ok(warning);
});

// ---------------------------------------------------------------------------
// Phase 8 (Plan 08-03 Task 1) — the computeReputation http branch (HTTP-03).
//
// An io.http.* bundle has NO GitHub org, so the http branch NEVER emits
// verified-org or host-popularity (D-07 — DNS never reaches the GitHub-verified
// tier). Instead it reads the threaded dnsVerify result (opts.dnsResult) and
// emits exactly one dated-factual signal:
//   - dns-verified-domain → "DNS TXT challenge passed for <domain> on <date>."
//   - dns-stale           → "DNS verification stale (last passed <date>); re-challenge pending."
//   - dns-pending         → reputation-pending "DNS verification pending."
// Every detail is dated factual copy, NEVER a verdict (D-07/D-08).
// ---------------------------------------------------------------------------

/** An http-sourced manifest fixture (io.http.<domain> namespace). */
const HTTP_MANIFEST = {
  schema_version: 1,
  name: "ga4-ecommerce",
  namespace: "io.http.example.com",
  description: "test",
  version: "1.0.0",
  source: { type: "http", url: "https://example.com/bundle.tar.gz", path: "", ref: "" },
  kind: "knowledge",
  categories: [],
};

test("http source: dns-verified-domain → dns-verified-domain signal with dated factual detail (D-07)", async () => {
  const dnsResult = {
    state: "dns-verified-domain",
    dns_verified_at: "2026-08-05T00:00:00.000Z",
    token: "io.http.example.com/ga4-ecommerce",
  };
  const { reputation, warning } = await computeReputation(HTTP_MANIFEST, undefined, { dnsResult });
  assert.equal(warning, undefined, "no warning on the http success path");
  assert.ok(reputation, "reputation block present (http branch)");
  assert.equal(reputation.source_type, "http");
  const dns = reputation.signals.find((s) => s.kind === "dns-verified-domain");
  assert.ok(dns, "dns-verified-domain signal present");
  assert.equal(dns.value, "example.com", "value is the domain");
  assert.match(dns.detail, /DNS TXT challenge passed for example\.com on 2026-08-05\./);
  // NEVER verified-org / host-popularity for http (D-07).
  assert.equal(reputation.signals.find((s) => s.kind === "verified-org"), undefined);
  assert.equal(reputation.signals.find((s) => s.kind === "host-popularity"), undefined);
});

test("http source: dns-stale → dns-stale signal, dated re-challenge detail (D-05, never a verdict)", async () => {
  const dnsResult = { state: "dns-stale", token: undefined };
  const priorDnsBlock = { dns_verified_at: "2026-06-28T00:00:00.000Z" };
  const { reputation } = await computeReputation(HTTP_MANIFEST, undefined, { dnsResult, priorDnsBlock });
  const stale = reputation.signals.find((s) => s.kind === "dns-stale");
  assert.ok(stale, "dns-stale signal present");
  assert.match(stale.detail, /DNS verification stale \(last passed 2026-06-28\); re-challenge pending\./);
  // NEVER verified-org / host-popularity for http.
  assert.equal(reputation.signals.find((s) => s.kind === "verified-org"), undefined);
  assert.equal(reputation.signals.find((s) => s.kind === "host-popularity"), undefined);
});

test("http source: dns-pending → reputation-pending signal, NO verified-org (D-07)", async () => {
  const dnsResult = { state: "dns-pending", token: undefined };
  const { reputation } = await computeReputation(HTTP_MANIFEST, undefined, { dnsResult });
  const pending = reputation.signals.find((s) => s.kind === "reputation-pending");
  assert.ok(pending, "dns-pending degrades to reputation-pending signal");
  assert.match(pending.detail, /DNS verification pending\./);
  assert.equal(reputation.signals.find((s) => s.kind === "verified-org"), undefined);
  assert.equal(reputation.signals.find((s) => s.kind === "host-popularity"), undefined);
});

test("http source: no dnsResult threaded → reputation-pending (defensive default)", async () => {
  const { reputation } = await computeReputation(HTTP_MANIFEST, undefined, {});
  const pending = reputation.signals.find((s) => s.kind === "reputation-pending");
  assert.ok(pending, "absent dnsResult → reputation-pending");
  assert.equal(reputation.signals.find((s) => s.kind === "dns-verified-domain"), undefined);
});

test("http source: the http branch NEVER makes a GitHub REST call (no /repos, /users, /orgs)", async () => {
  const calls = [];
  const gh = async (path) => {
    calls.push(path);
    throw new Error(`mock gh should NOT be called for http source: ${path}`);
  };
  const dnsResult = { state: "dns-verified-domain", dns_verified_at: "2026-08-05T00:00:00.000Z" };
  const { reputation } = await computeReputation(HTTP_MANIFEST, undefined, { gh, dnsResult });
  assert.ok(reputation, "reputation computed via the http branch (no gh call needed)");
  assert.equal(calls.length, 0, "the http branch must never invoke the GitHub fetcher");
});
