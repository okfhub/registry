// dns-verify.test.mjs — DNS TXT challenge verification tests (Phase 8, Plan 08-02).
//
// Mirrors reputation.test.mjs's node:test + mock-injection shape. The load-bearing
// seam is opts.resolver — a mocked { resolveNs, resolve4, resolveTxt, setServers }
// object (mirrors reputation.mjs's opts.gh) so every DNS call is mockable with NO
// live DNS in CI (Wave-0 deliverable, 08-VALIDATION.md). Covers HTTP-02 (D-02
// authoritative-NS 4-step sequence, D-03 deterministic TXT name, Keybase #1614
// chunk-join) and HTTP-03 (D-05 30-day staleness window, never-a-verdict states).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  challengeRecordName,
  verifyDnsChallenge,
  dnsVerify,
  DNS_STALE_WINDOW_MS,
  DNS_LOGIC_VERSION,
} from "../../scripts/checks/dns-verify.mjs";

/** A validated http-sourced manifest fixture (mirrors reputation.test.mjs's
 *  MANIFEST shape, adapted for io.http.<domain>). */
const MANIFEST = {
  schema_version: 1,
  name: "ga4-ecommerce",
  namespace: "io.http.example.com",
  description: "test",
  version: "1.0.0",
  source: { type: "http", url: "https://example.com/bundle.tar.gz", path: "", ref: "" },
  kind: "knowledge",
  categories: [],
};

/** The deterministic token8 for the fixture (sha8 of namespace/name@sourceUrl),
 *  computed independently in the test so challengeRecordName is self-validating. */
function expectedToken8(namespace, name, sourceUrl) {
  return createHash("sha256").update(`${namespace}/${name}@${sourceUrl}`).digest("hex").slice(0, 8);
}

/** Build a mock resolver object (the opts.resolver injection seam). Returns an
 *  object exposing resolveNs/resolve4/resolveTxt + setServers (which records its
 *  calls into the attached setServersCalls array so tests can assert the
 *  authoritative-NS pin used an IP, not a hostname — D-02).
 *
 *  Each of resolveNs/resolve4/resolveTxt accepts either a canned value or a
 *  function(host|name) => value|throw. Defaults make the happy path a one-liner. */
function makeMockResolver({ resolveNs, resolve4, resolveTxt } = {}) {
  const setServersCalls = [];
  return {
    setServersCalls,
    async resolveNs(domain) {
      if (typeof resolveNs === "function") return resolveNs(domain);
      return resolveNs ?? ["ns1.example.com"];
    },
    async resolve4(host) {
      if (typeof resolve4 === "function") return resolve4(host);
      return resolve4 ?? ["1.2.3.4"];
    },
    setServers(servers) {
      setServersCalls.push(servers);
    },
    async resolveTxt(name) {
      if (typeof resolveTxt === "function") return resolveTxt(name);
      return resolveTxt ?? [];
    },
  };
}

test("DNS_STALE_WINDOW_MS is 30 days in milliseconds (D-05)", () => {
  assert.equal(DNS_STALE_WINDOW_MS, 30 * 24 * 60 * 60 * 1000);
});

test("DNS_LOGIC_VERSION is a positive integer", () => {
  assert.equal(typeof DNS_LOGIC_VERSION, "number");
  assert.ok(DNS_LOGIC_VERSION >= 1);
});

test("challengeRecordName is deterministic: _okfhub.<token8>.<domain> (D-03)", () => {
  const ns = "io.http.example.com";
  const name = "ga4-ecommerce";
  const url = "https://example.com/bundle.tar.gz";
  const domain = "example.com";
  const got = challengeRecordName(ns, name, url, domain);
  const token8 = expectedToken8(ns, name, url);
  assert.equal(got, `_okfhub.${token8}.${domain}`);
  // Underscore prefix per RFC 8552 (D-03).
  assert.ok(got.startsWith("_okfhub."));
});

test("challengeRecordName is stable across calls with identical inputs (re-challenge queries the same name)", () => {
  const a = challengeRecordName("io.http.example.com", "x", "https://e.com/t.tar.gz", "example.com");
  const b = challengeRecordName("io.http.example.com", "x", "https://e.com/t.tar.gz", "example.com");
  assert.equal(a, b);
});

test("challengeRecordName differs per bundle (per-bundle token defeats the concurrent/wildcard race — D-03, Pitfall 1.2)", () => {
  const a = challengeRecordName("io.http.example.com", "bundle-a", "https://e.com/a.tar.gz", "example.com");
  const b = challengeRecordName("io.http.example.com", "bundle-b", "https://e.com/b.tar.gz", "example.com");
  assert.notEqual(a, b);
});

test("verifyDnsChallenge success: resolveTxt returns the matching value (chunks joined — Keybase #1614)", async () => {
  const expected = "okfhub-verify=io.http.example.com/ga4-ecommerce";
  const resolver = makeMockResolver({
    resolveTxt: () => [[expected]], // single record, one chunk
  });
  const ok = await verifyDnsChallenge("_okfhub.abcdef01.example.com", "example.com", expected, { resolver });
  assert.equal(ok, true);
});

test("verifyDnsChallenge joins multi-chunk TXT values before comparing (Keybase #1614)", async () => {
  // resolveTxt returns string[][] — a single record split into two chunks that
  // must be joined ("") before comparison.
  const expected = "okfhub-verify=io.http.example.com/ga4-ecommerce";
  const mid = Math.floor(expected.length / 2);
  const resolver = makeMockResolver({
    resolveTxt: () => [[expected.slice(0, mid), expected.slice(mid)]],
  });
  const ok = await verifyDnsChallenge("_okfhub.abcdef01.example.com", "example.com", expected, { resolver });
  assert.equal(ok, true);
});

test("verifyDnsChallenge scans ALL records: only one of several TXT records matches", async () => {
  const expected = "okfhub-verify=io.http.example.com/ga4-ecommerce";
  const resolver = makeMockResolver({
    resolveTxt: () => [
      ["v=spf1 -all"], // unrelated SPF record
      [expected], // the matching challenge record (not first)
      ["some-other=thing"],
    ],
  });
  const ok = await verifyDnsChallenge("_okfhub.abcdef01.example.com", "example.com", expected, { resolver });
  assert.equal(ok, true);
});

test("verifyDnsChallenge returns false when NO record matches the expected value", async () => {
  const resolver = makeMockResolver({
    resolveTxt: () => [["v=spf1 -all"], ["something-else=foo"]],
  });
  const ok = await verifyDnsChallenge("_okfhub.abcdef01.example.com", "example.com", "okfhub-verify=nope", { resolver });
  assert.equal(ok, false);
});

test("verifyDnsChallenge returns false on NXDOMAIN/ENOTFOUND (resolveTxt throws)", async () => {
  const resolver = makeMockResolver({
    resolveTxt() {
      const e = new Error("queryTxt ENOTFOUND _okfhub.abcdef01.example.com");
      e.code = "ENOTFOUND";
      throw e;
    },
  });
  const ok = await verifyDnsChallenge("_okfhub.abcdef01.example.com", "example.com", "okfhub-verify=x", { resolver });
  assert.equal(ok, false);
});

test("verifyDnsChallenge returns false when resolveNs returns an empty nameserver list", async () => {
  const resolver = makeMockResolver({ resolveNs: () => [] });
  const ok = await verifyDnsChallenge("_okfhub.abcdef01.example.com", "example.com", "okfhub-verify=x", { resolver });
  assert.equal(ok, false);
  // setServers never called because there was no NS to pin.
  assert.equal(resolver.setServersCalls.length, 0);
});

test("verifyDnsChallenge pins the authoritative NS by IP via setServers (D-02 — IP, not hostname)", async () => {
  const expected = "okfhub-verify=io.http.example.com/ga4-ecommerce";
  const resolver = makeMockResolver({
    resolveNs: () => ["ns1.example.com"],
    resolve4: () => ["162.159.0.33"], // an IP, not a hostname
    resolveTxt: () => [[expected]],
  });
  await verifyDnsChallenge("_okfhub.abcdef01.example.com", "example.com", expected, { resolver });
  assert.equal(resolver.setServersCalls.length, 1, "setServers called exactly once");
  const servers = resolver.setServersCalls[0];
  assert.ok(Array.isArray(servers), "setServers receives an array");
  assert.equal(servers.length, 1);
  // D-02: the pinned server MUST be an IP (setServers rejects hostnames —
  // ERR_INVALID_IP_ADDRESS). Assert it is an IPv4 dotted-quad, not "ns1...".
  assert.match(servers[0], /^\d+\.\d+\.\d+\.\d+$/, "pinned server is an IP, not a hostname");
});

test("verifyDnsChallenge tries the NEXT NS when resolve4 fails on the first (CONTEXT resolve4 failure path)", async () => {
  const expected = "okfhub-verify=io.http.example.com/ga4-ecommerce";
  const resolve4Calls = [];
  const resolver = makeMockResolver({
    resolveNs: () => ["ns1.example.com", "ns2.example.com"],
    resolve4(host) {
      resolve4Calls.push(host);
      if (host === "ns1.example.com") {
        const e = new Error("queryA ENOTFOUND ns1.example.com");
        e.code = "ENOTFOUND";
        throw e;
      }
      return ["5.6.7.8"]; // ns2 resolves
    },
    resolveTxt: () => [[expected]],
  });
  const ok = await verifyDnsChallenge("_okfhub.abcdef01.example.com", "example.com", expected, { resolver });
  assert.equal(ok, true);
  assert.deepEqual(resolve4Calls, ["ns1.example.com", "ns2.example.com"], "fell through to the second NS");
  // Pinned on the second NS's IP.
  assert.match(resolver.setServersCalls[0][0], /^\d+\.\d+\.\d+\.\d+$/);
});

test("verifyDnsChallenge returns false when ALL authoritative NS resolve4 calls fail", async () => {
  const resolver = makeMockResolver({
    resolveNs: () => ["ns1.example.com", "ns2.example.com"],
    resolve4() {
      const e = new Error("queryA ENOTFOUND");
      e.code = "ENOTFOUND";
      throw e;
    },
    resolveTxt: () => [["okfhub-verify=x"]],
  });
  const ok = await verifyDnsChallenge("_okfhub.abcdef01.example.com", "example.com", "okfhub-verify=x", { resolver });
  assert.equal(ok, false, "no resolvable NS IP → cannot pin → false (caller polls / degrades)");
  assert.equal(resolver.setServersCalls.length, 0, "never pinned without an IP");
});

test("dnsVerify fresh success → dns-verified-domain + ISO dns_verified_at (no warning)", async () => {
  const expected = "okfhub-verify=io.http.example.com/ga4-ecommerce";
  const resolver = makeMockResolver({ resolveTxt: () => [[expected]] });
  const result = await dnsVerify(MANIFEST, undefined, { resolver, initialDelay: 0, budget: 0 });
  assert.equal(result.state, "dns-verified-domain");
  assert.equal(result.warning, undefined);
  assert.ok(typeof result.dns_verified_at === "string" && result.dns_verified_at.length > 0);
  // ISO 8601 parseable.
  assert.ok(!Number.isNaN(Date.parse(result.dns_verified_at)));
  // The returned token carries the bundle identity (namespace/name).
  assert.equal(result.token, "io.http.example.com/ga4-ecommerce");
});

test("dnsVerify stale priorBlock (>30d) + live failure → dns-stale (D-05)", async () => {
  // A prior verification 31 days ago; the live re-challenge fails (no match).
  const stale = new Date(Date.now() - (31 * 24 * 60 * 60 * 1000)).toISOString();
  const priorBlock = { dns_verified_at: stale, state: "dns-verified-domain" };
  const resolver = makeMockResolver({ resolveTxt: () => [["v=spf1 -all"]] }); // no match
  const result = await dnsVerify(MANIFEST, priorBlock, { resolver, initialDelay: 0, budget: 0 });
  assert.equal(result.state, "dns-stale");
  assert.ok(result.warning, "dns-stale carries a warning/detail");
  // The stale detail must NOT contain a verdict word (HTTP-03 never-a-verdict).
  assert.ok(!/\b(verified-safe|trusted|approved)\b/i.test(result.warning));
});

test("dnsVerify within-window priorBlock + transient failure → dns-verified-domain (carry-forward ORIGINAL date)", async () => {
  // A prior verification 5 days ago (well within 30d); the live re-challenge fails
  // transiently (no match / NXDOMAIN). Within the window → carry forward the
  // ORIGINAL dns_verified_at (the rendered date shows WHEN the proof is FROM).
  const recent = new Date(Date.now() - (5 * 24 * 60 * 60 * 1000)).toISOString();
  const priorBlock = { dns_verified_at: recent, state: "dns-verified-domain" };
  const resolver = makeMockResolver({
    resolveTxt() {
      const e = new Error("queryTxt ENOTFOUND");
      e.code = "ENOTFOUND";
      throw e;
    },
  });
  const result = await dnsVerify(MANIFEST, priorBlock, { resolver, initialDelay: 0, budget: 0 });
  assert.equal(result.state, "dns-verified-domain", "within window → carry-forward, not stale/pending");
  assert.equal(result.dns_verified_at, recent, "ORIGINAL dns_verified_at preserved (not refreshed)");
  assert.equal(result.warning, undefined);
});

test("dnsVerify never-verified + failure → dns-pending (never throws)", async () => {
  const resolver = makeMockResolver({
    resolveTxt() {
      const e = new Error("queryTxt ENOTFOUND");
      e.code = "ENOTFOUND";
      throw e;
    },
  });
  const result = await dnsVerify(MANIFEST, undefined, { resolver, initialDelay: 0, budget: 0 });
  assert.equal(result.state, "dns-pending");
  assert.equal(result.dns_verified_at, undefined);
  assert.ok(result.warning);
});

test("dnsVerify boundary: priorBlock exactly 29d ago + failure → still within window (carry-forward)", async () => {
  const justInside = new Date(Date.now() - (29 * 24 * 60 * 60 * 1000)).toISOString();
  const priorBlock = { dns_verified_at: justInside, state: "dns-verified-domain" };
  const resolver = makeMockResolver({ resolveTxt: () => [] });
  const result = await dnsVerify(MANIFEST, priorBlock, { resolver, initialDelay: 0, budget: 0 });
  assert.equal(result.state, "dns-verified-domain");
  assert.equal(result.dns_verified_at, justInside);
});

test("dnsVerify boundary: priorBlock exactly 31d ago + failure → dns-stale", async () => {
  const justOver = new Date(Date.now() - (31 * 24 * 60 * 60 * 1000)).toISOString();
  const priorBlock = { dns_verified_at: justOver, state: "dns-verified-domain" };
  const resolver = makeMockResolver({ resolveTxt: () => [] });
  const result = await dnsVerify(MANIFEST, priorBlock, { resolver, initialDelay: 0, budget: 0 });
  assert.equal(result.state, "dns-stale");
});

test("dnsVerify degrades to dns-pending and NEVER throws on an unexpected error (per-bundle isolation)", async () => {
  const resolver = makeMockResolver({
    resolveNs() {
      throw new Error("unexpected catastrophic DNS error");
    },
  });
  // Must not throw — one bad bundle must never block the index.
  const result = await dnsVerify(MANIFEST, undefined, { resolver, initialDelay: 0, budget: 0 });
  assert.equal(result.state, "dns-pending");
  assert.ok(result.warning);
  assert.match(result.warning, /dns/i);
});

test("dnsVerify non-http source type → dns-pending + warning (only io.http.* is DNS-challenged)", async () => {
  const ghManifest = {
    ...MANIFEST,
    namespace: "io.github.google",
    source: { type: "github", url: "https://github.com/google/kc", path: "", ref: "main" },
  };
  const resolver = makeMockResolver();
  const result = await dnsVerify(ghManifest, undefined, { resolver });
  assert.equal(result.state, "dns-pending");
  assert.ok(result.warning);
});

test("dnsVerify detail strings are sanitized (no raw markdown-active chars from a hostile domain — T-07-INJECT)", async () => {
  // A hostile namespace whose domain segment contains markdown-active chars.
  // (The registry regex would normally reject these, but defense-in-depth: any
  // detail carrying the domain must be backslash-escaped via sanitizeForComment.)
  const hostile = {
    ...MANIFEST,
    namespace: "io.http.evil<img>.com",
    source: { type: "http", url: "https://evil<img>.com/b.tar.gz", path: "", ref: "" },
  };
  const stale = new Date(Date.now() - (40 * 24 * 60 * 60 * 1000)).toISOString();
  const resolver = makeMockResolver({ resolveTxt: () => [["nope"]] });
  const result = await dnsVerify(hostile, { dns_verified_at: stale, state: "dns-verified-domain" }, {
    resolver,
    initialDelay: 0,
    budget: 0,
  });
  assert.equal(result.state, "dns-stale");
  assert.ok(result.warning);
  // The raw <img> must NOT appear — it must be backslash-escaped.
  assert.ok(!result.warning.includes("<img>"), "no raw <img> in the detail");
});
