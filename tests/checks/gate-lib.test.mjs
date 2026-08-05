// gate-lib.test.mjs — tests for the namespace field/path consistency check
// (audit finding: without it, an attacker could pollute registry.json).
//
// These exercise evaluatePullRequest directly with a stubbed gh() so no network.
// The pure check functions (ownership/path-scope/schema/rate-limit) have their
// own test files; this file covers the ORCHESTRATION-level guard that sits
// between schema and ownership in gate-lib.mjs.

import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluatePullRequest } from "../../scripts/checks/gate-lib.mjs";

const REPO = "okfhub/registry";

/** Build a stub gh() that returns canned responses for the API calls
 *  evaluatePullRequest makes: pulls/files, pulls/{n}, contents/{path},
 *  collaborators/{user}/permission (infra-PR privilege check). */
function makeGh({ changedFiles = [], manifestJson = null, manifestPath, permission = null }) {
  return async function gh(path, init = {}) {
    // GET /repos/{repo}/collaborators/{user}/permission — infra-PR gate.
    if (path.includes("/collaborators/") && path.endsWith("/permission")) {
      if (permission === null) return new Response("not found", { status: 404 });
      const push = ["admin", "maintain", "write", "triage"].includes(permission);
      return new Response(
        JSON.stringify({ permission, permissions: { admin: permission === "admin", maintain: permission === "maintain", push, triage: permission === "triage", pull: true } }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    // GET /repos/{repo}/pulls/{n}/files
    if (path.includes("/files?per_page=100")) {
      return new Response(JSON.stringify(changedFiles.map((f) => ({ filename: f }))), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    // GET /repos/{repo}/pulls/{n}
    if (path.match(/\/pulls\/\d+$/)) {
      return new Response(JSON.stringify({ head: { sha: "abc123" } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    // GET /repos/{repo}/contents/{path}?ref=...
    if (path.includes("/contents/")) {
      if (manifestJson === null) {
        return new Response("not found", { status: 404 });
      }
      const content = Buffer.from(JSON.stringify(manifestJson)).toString("base64");
      return new Response(
        JSON.stringify({ encoding: "base64", content }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return new Response("{}", { status: 200 });
  };
}

/** A valid io.http.* manifest fixture (Phase 8). */
function httpManifest(over = {}) {
  return {
    schema_version: 1,
    name: "my-http-bundle",
    namespace: "io.http.example.com",
    description: "http-sourced",
    version: "1.0.0",
    source: { type: "http", url: "https://example.com/bundles/my-http-bundle.tar.gz" },
    kind: "knowledge",
    categories: [],
    ...over,
  };
}

test("infra PR (no manifest) from a push-permission collaborator → APPROVED, infra: true", async () => {
  // A maintainer's maintenance PR: scripts/, tests/, .github/ changes, no manifest.
  // The gate must pass (green check) so the required-status `check` is satisfiable,
  // and mark infra:true so gate-merge does NOT auto-merge it (human merges).
  const gh = makeGh({
    changedFiles: ["scripts/checks/gate-lib.mjs", "tests/checks/gate-lib.test.mjs"],
    permission: "admin", // maintainer with push permission
  });
  const pr = { number: 5, user: { login: "asagajda" }, head: { sha: "mno345" } };
  const result = await evaluatePullRequest(gh, REPO, pr);
  assert.equal(result.passed, true, "infra PR from a push collaborator must pass");
  assert.equal(result.infra, true, "infra PR must be flagged infra:true");
  assert.equal(result.manifestPath, null);
});

test("infra PR (no manifest) from a read-only/fork author → BLOCKED (no privilege escalation)", async () => {
  // A fork/external author's PR touching scripts/ with no manifest must stay RED.
  // This is the security invariant: a fork cannot auto-merge code into scripts/
  // or .github/workflows/ via the infra path — only push collaborators can.
  const gh = makeGh({
    changedFiles: ["scripts/checks/gate-lib.mjs"],
    permission: "read", // external contributor, no push permission
  });
  const pr = { number: 6, user: { login: "rando" }, head: { sha: "pqr678" } };
  const result = await evaluatePullRequest(gh, REPO, pr);
  assert.equal(result.passed, false, "infra PR from a read-only author must be blocked");
  assert.equal(result.infra, false);
  assert.match(result.reason, /no .* manifest found/);
});

test("infra PR from a non-collaborator (404 on permission lookup) → BLOCKED, fail-closed", async () => {
  // The permission endpoint returns 404 for a user with no explicit collaborator
  // entry. isMaintainer must fail-closed (treat as not-a-maintainer), not approve.
  const gh = makeGh({
    changedFiles: [".github/workflows/build-registry.yml"],
    permission: null, // 404
  });
  const pr = { number: 7, user: { login: "stranger" }, head: { sha: "stu901" } };
  const result = await evaluatePullRequest(gh, REPO, pr);
  assert.equal(result.passed, false, "fail-closed on a permission-lookup 404");
});

test("namespace field/path mismatch → BLOCKED (the exploit this guard prevents)", async () => {
  // The exploit: file at io.github.alice/bitcoin.json, but manifest.namespace = io.github.google.
  // alice owns the PATH, but her field claims google's namespace.
  const gh = makeGh({
    changedFiles: ["io.github.alice/bitcoin.json"],
    manifestJson: {
      schema_version: 1,
      name: "bitcoin",
      namespace: "io.github.google", // ← impersonation attempt
      description: "x",
      version: "9.9.9",
      source: { type: "github", url: "https://github.com/alice/evil", path: "", ref: "main" },
    },
  });
  const pr = { number: 1, user: { login: "alice" }, head: { sha: "abc123" } };
  const result = await evaluatePullRequest(gh, REPO, pr);
  assert.equal(result.passed, false, "field/path mismatch must be blocked");
  assert.match(result.reason, /namespace.*declares.*io\.github\.google.*but lives at.*io\.github\.alice/);
});

test("namespace field/path match (the CLI's by-construction case) → not blocked by this check", async () => {
  // The normal case the CLI produces: field and path agree.
  const gh = makeGh({
    changedFiles: ["io.github.alice/my-bundle.json"],
    manifestJson: {
      schema_version: 1,
      name: "my-bundle",
      namespace: "io.github.alice", // ← matches path
      description: "x",
      version: "1.0.0",
      source: { type: "github", url: "https://github.com/alice/repo", path: "", ref: "main" },
    },
  });
  const pr = { number: 2, user: { login: "alice" }, head: { sha: "def456" } };
  const result = await evaluatePullRequest(gh, REPO, pr);
  // Ownership/path-scope pass (alice owns io.github.alice). This should NOT be
  // blocked by the namespace check — it may be blocked later by rate-limit
  // (no policy file in the test env → no limits) or pass through. The point:
  // the reason must NOT mention the namespace mismatch.
  if (!result.passed) {
    assert.doesNotMatch(
      result.reason,
      /namespace.*declares.*but lives at/,
      "field/path-consistent manifest must not trip the namespace guard",
    );
  }
});

test("namespace field/path match for an ORG namespace → not blocked by this check", async () => {
  // alice is a member of the 'acme' org; publishes into io.github.acme/.
  const gh = makeGh({
    changedFiles: ["io.github.acme/widget.json"],
    manifestJson: {
      schema_version: 1,
      name: "widget",
      namespace: "io.github.acme",
      description: "x",
      version: "1.0.0",
      source: { type: "github", url: "https://github.com/acme/widget", path: "", ref: "main" },
    },
  });
  // Stub the public_members check: alice IS a member of acme.
  const ghWithMember = async (path, init) => {
    if (path.includes("/public_members/")) return new Response(null, { status: 204 });
    return gh(path, init);
  };
  const pr = { number: 3, user: { login: "alice" }, head: { sha: "ghi789" } };
  const result = await evaluatePullRequest(ghWithMember, REPO, pr);
  if (!result.passed) {
    assert.doesNotMatch(result.reason, /namespace.*declares.*but lives at/);
  }
});

test("namespace field case mismatch (io.github.Alice vs path io.github.alice) → BLOCKED", async () => {
  // The guard compares canonical lowercase; a case trick shouldn't slip through.
  const gh = makeGh({
    changedFiles: ["io.github.alice/x.json"],
    manifestJson: {
      schema_version: 1,
      name: "x",
      namespace: "io.github.Alice",
      description: "x",
      version: "1.0.0",
      source: { type: "github", url: "https://github.com/alice/x", path: "", ref: "main" },
    },
  });
  const pr = { number: 4, user: { login: "alice" }, head: { sha: "jkl012" } };
  const result = await evaluatePullRequest(gh, REPO, pr);
  // Note: io.github.Alice fails the schema regex first ([a-z0-9-]+), so it's
  // blocked at schema. This test documents that case tricks are caught (by
  // schema here); the namespace guard is the backstop for regex-valid cases.
  assert.equal(result.passed, false);
});

// ---------------------------------------------------------------------------
// Phase 8: io.http.* namespace-family dispatch + DNS-ownership check.
// The gate's io.http.* branch re-derives the deterministic token, queries the
// authoritative NS via an injected verifyChallenge, and passes only if the TXT
// matches. Fail-closed on a thrown resolver / NXDOMAIN-within-window (T-08-GATE).
// The github org-membership path is UNCHANGED (the earlier tests cover it).
// ---------------------------------------------------------------------------

test("io.http.* PR with a matching DNS TXT → APPROVED (DNS-ownership proven)", async () => {
  const gh = makeGh({
    changedFiles: ["io.http.example.com/my-http-bundle.json"],
    manifestJson: httpManifest(),
  });
  const pr = { number: 10, user: { login: "anyone" }, head: { sha: "http01" } };
  // Inject verifyDns → returns true (TXT present on the authoritative NS).
  const result = await evaluatePullRequest(gh, REPO, pr, {
    verifyDns: async () => true,
    dnsRetryInterval: 0,
    dnsRetryBudget: 0,
  });
  assert.equal(result.passed, true, "http PR with a matching TXT must pass");
  assert.equal(result.org, null); // org is null for http (no github org)
});

test("io.http.* PR with verifyDns returning false (TXT absent) → BLOCKED", async () => {
  const gh = makeGh({
    changedFiles: ["io.http.example.com/my-http-bundle.json"],
    manifestJson: httpManifest(),
  });
  const pr = { number: 11, user: { login: "anyone" }, head: { sha: "http02" } };
  const result = await evaluatePullRequest(gh, REPO, pr, {
    verifyDns: async () => false, // TXT not present on the authoritative NS
    dnsRetryInterval: 0,
    dnsRetryBudget: 0, // single shot — no retry wait
  });
  assert.equal(result.passed, false);
  assert.match(result.reason, /DNS TXT challenge NOT verified/);
});

test("io.http.* PR with a THROWN resolver (resolver error) → BLOCKED, fail-closed (T-08-GATE)", async () => {
  const gh = makeGh({
    changedFiles: ["io.http.example.com/my-http-bundle.json"],
    manifestJson: httpManifest(),
  });
  const pr = { number: 12, user: { login: "anyone" }, head: { sha: "http03" } };
  const result = await evaluatePullRequest(gh, REPO, pr, {
    verifyDns: async () => {
      throw new Error("EAI_AGAIN resolver timeout");
    },
    dnsRetryInterval: 0,
    dnsRetryBudget: 0,
  });
  assert.equal(result.passed, false, "a thrown resolver must fail-closed (block)");
  assert.match(result.reason, /failing safe/);
});

test("io.http.* namespace field/path mismatch → BLOCKED (T-08-CONSISTENCY)", async () => {
  // Manifest namespace field claims a different http domain than its path.
  const gh = makeGh({
    changedFiles: ["io.http.example.com/spoof.json"],
    manifestJson: httpManifest({ namespace: "io.http.evil.com", name: "spoof" }),
  });
  const pr = { number: 13, user: { login: "anyone" }, head: { sha: "http04" } };
  const result = await evaluatePullRequest(gh, REPO, pr, {
    verifyDns: async () => true,
    dnsRetryInterval: 0,
    dnsRetryBudget: 0,
  });
  assert.equal(result.passed, false);
  assert.match(result.reason, /namespace.*declares.*io\.http\.evil\.com.*but lives at.*io\.http\.example\.com/);
});

test("io.http.* PR with a github-namespaced file mixed in → BLOCKED at path-scope (cross-namespace)", async () => {
  const gh = makeGh({
    changedFiles: ["io.http.example.com/a.json", "io.github.alice/b.json"],
    manifestJson: httpManifest(),
  });
  const pr = { number: 14, user: { login: "anyone" }, head: { sha: "http05" } };
  const result = await evaluatePullRequest(gh, REPO, pr, {
    verifyDns: async () => true,
    dnsRetryInterval: 0,
    dnsRetryBudget: 0,
  });
  assert.equal(result.passed, false);
  assert.match(result.reason, /path-scope/);
  assert.match(result.reason, /cross-namespace/);
});

test("io.http.* gate re-derives the SAME token the publish CLI computes (challengeRecordName)", async () => {
  // The gate's http branch calls challengeRecordName(namespace, name, sourceUrl, domain).
  // This test confirms the gate threaded those exact fields to the verifier by
  // asserting the recordName + expectedValue the injected verifyDns received
  // match the deterministic token for this manifest.
  const gh = makeGh({
    changedFiles: ["io.http.example.com/my-http-bundle.json"],
    manifestJson: httpManifest(),
  });
  const pr = { number: 15, user: { login: "anyone" }, head: { sha: "http06" } };
  let seen = null;
  const result = await evaluatePullRequest(gh, REPO, pr, {
    verifyDns: async (recordName, domain, expectedValue) => {
      seen = { recordName, domain, expectedValue };
      return true;
    },
    dnsRetryInterval: 0,
    dnsRetryBudget: 0,
  });
  assert.equal(result.passed, true);
  assert.ok(seen, "verifyDns was called");
  // The expectedValue is the deterministic okfhub-verify=<namespace>/<name>.
  assert.equal(seen.expectedValue, "okfhub-verify=io.http.example.com/my-http-bundle");
  assert.equal(seen.domain, "example.com");
  // The recordName matches dns-verify.mjs's challengeRecordName byte-for-byte.
  const { challengeRecordName } = await import("../../scripts/checks/dns-verify.mjs");
  const expectedName = challengeRecordName(
    "io.http.example.com",
    "my-http-bundle",
    "https://example.com/bundles/my-http-bundle.tar.gz",
    "example.com",
  );
  assert.equal(seen.recordName, expectedName);
});

test("io.http.* propagation-retry loop: TXT appears on the 3rd attempt → pass (within budget)", async () => {
  // The propagation-retry loop retries every interval until the budget. A TXT
  // that appears after 2 misses + 1 hit passes (simulates a publisher who added
  // the TXT just before the gate ran). Interval/budget overridden to keep the
  // test fast.
  const gh = makeGh({
    changedFiles: ["io.http.example.com/my-http-bundle.json"],
    manifestJson: httpManifest(),
  });
  const pr = { number: 16, user: { login: "anyone" }, head: { sha: "http07" } };
  let calls = 0;
  const result = await evaluatePullRequest(gh, REPO, pr, {
    // Override the REAL verifier (not opts.verifyDns) — exercise verifyDnsWithRetry.
    dnsRetryInterval: 1, // 1ms — effectively immediate
    dnsRetryBudget: 5000, // 5s budget — enough for a few 1ms retries
    // Stub the real resolver used by verifyDnsChallenge. opts.verifyDns short-
    // circuits the retry loop, so we inject at the resolver level to exercise it.
    resolver: {
      resolveNs: async () => ["ns1.example.com"],
      resolve4: async () => ["1.2.3.4"],
      setServers: () => {},
      resolveTxt: async () => {
        calls += 1;
        if (calls < 3) throw new Error("ENOTFOUND"); // first 2 attempts: not present
        return [["okfhub-verify=io.http.example.com/my-http-bundle"]]; // 3rd: present
      },
    },
  });
  assert.equal(result.passed, true, "TXT appearing on the 3rd attempt passes within the budget");
  assert.ok(calls >= 3, `the retry loop made multiple attempts (saw ${calls})`);
});

test("io.http.* propagation-retry loop: TXT never appears within budget → BLOCKED", async () => {
  const gh = makeGh({
    changedFiles: ["io.http.example.com/my-http-bundle.json"],
    manifestJson: httpManifest(),
  });
  const pr = { number: 17, user: { login: "anyone" }, head: { sha: "http08" } };
  const result = await evaluatePullRequest(gh, REPO, pr, {
    dnsRetryInterval: 1,
    dnsRetryBudget: 5, // 5ms budget — exhausted quickly, TXT never appears
    resolver: {
      resolveNs: async () => ["ns1.example.com"],
      resolve4: async () => ["1.2.3.4"],
      setServers: () => {},
      resolveTxt: async () => {
        throw new Error("ENOTFOUND"); // never present
      },
    },
  });
  assert.equal(result.passed, false);
  assert.match(result.reason, /DNS TXT challenge NOT verified/);
});
