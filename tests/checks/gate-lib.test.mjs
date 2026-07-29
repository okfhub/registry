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
 *  evaluatePullRequest makes: pulls/files, pulls/{n}, contents/{path}. */
function makeGh({ changedFiles = [], manifestJson = null, manifestPath }) {
  return async function gh(path, init = {}) {
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
