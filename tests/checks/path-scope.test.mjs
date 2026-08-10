// path-scope.test.mjs — D-07 defense-in-depth checks (Phase 8 namespace-family).
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkPathScope, namespaceOrgFromPath, namespaceFamilyFromPath } from "../../scripts/checks/path-scope.mjs";

test("single valid file under own namespace → pass", () => {
  const r = checkPathScope({
    changedFiles: ["io.github.stripe/api-knowledge.json"],
    org: "stripe",
  });
  assert.equal(r.passed, true);
});

test("multiple files, same namespace → pass (a PR can add/update several bundles under one org)", () => {
  const r = checkPathScope({
    changedFiles: [
      "io.github.stripe/a.json",
      "io.github.stripe/b.json",
      "io.github.stripe/sub/c.json",
    ],
    org: "stripe",
  });
  assert.equal(r.passed, true);
});

test("file in another namespace → REJECT (cross-namespace injection)", () => {
  const r = checkPathScope({
    changedFiles: ["io.github.google/ga4.json"],
    org: "stripe",
  });
  assert.equal(r.passed, false);
  assert.match(r.reason, /cross-namespace/);
});

test("registry.json touched → REJECT", () => {
  const r = checkPathScope({
    changedFiles: ["io.github.stripe/x.json", "registry.json"],
    org: "stripe",
  });
  assert.equal(r.passed, false);
  assert.match(r.reason, /registry\.json/);
});

test(".github/workflows touched → REJECT (workflow tampering)", () => {
  const r = checkPathScope({
    changedFiles: ["io.github.stripe/x.json", ".github/workflows/merge-gate.yml"],
    org: "stripe",
  });
  assert.equal(r.passed, false);
  assert.match(r.reason, /\.github/);
});

test(">1 namespace in one PR → REJECT", () => {
  const r = checkPathScope({
    changedFiles: ["io.github.stripe/a.json", "io.github.google/b.json"],
    org: "stripe",
  });
  assert.equal(r.passed, false);
});

test("empty changed-files → REJECT", () => {
  const r = checkPathScope({ changedFiles: [], org: "stripe" });
  assert.equal(r.passed, false);
});

test("namespaceOrgFromPath helper: extracts org or null", () => {
  assert.equal(namespaceOrgFromPath("io.github.stripe/x.json"), "stripe");
  assert.equal(namespaceOrgFromPath("io.github.google/sub/y.json"), "google");
  assert.equal(namespaceOrgFromPath("registry.json"), null);
  assert.equal(namespaceOrgFromPath(".github/workflows/x.yml"), null);
});

// ---------------------------------------------------------------------------
// Phase 8: namespace-family detection (io.http.<domain>/) + per-family prefix.
// ---------------------------------------------------------------------------

test("namespaceFamilyFromPath: github path → { family: 'github', segment: org }", () => {
  assert.deepEqual(namespaceFamilyFromPath("io.github.stripe/x.json"), {
    family: "github",
    segment: "stripe",
  });
});

test("namespaceFamilyFromPath: http path → { family: 'http', segment: domain }", () => {
  assert.deepEqual(namespaceFamilyFromPath("io.http.example.com/x.json"), {
    family: "http",
    segment: "example.com",
  });
});

test("namespaceFamilyFromPath: non-namespace path → { family: null, segment: null }", () => {
  assert.deepEqual(namespaceFamilyFromPath("registry.json"), { family: null, segment: null });
  assert.deepEqual(namespaceFamilyFromPath(".github/workflows/x.yml"), { family: null, segment: null });
});

test("http family: single file under io.http.<domain>/ → pass", () => {
  const r = checkPathScope({
    changedFiles: ["io.http.example.com/my-bundle.json"],
    family: "http",
    segment: "example.com",
  });
  assert.equal(r.passed, true);
});

test("http family: file in a DIFFERENT http domain → REJECT (cross-namespace)", () => {
  const r = checkPathScope({
    changedFiles: ["io.http.evil.com/injected.json"],
    family: "http",
    segment: "example.com",
  });
  assert.equal(r.passed, false);
  assert.match(r.reason, /cross-namespace/);
});

test("http family: a github-namespaced file in an http PR → REJECT (cross-family)", () => {
  // An io.github.* file sneaked into an io.http.* PR is cross-namespace injection.
  const r = checkPathScope({
    changedFiles: ["io.http.example.com/a.json", "io.github.alice/b.json"],
    family: "http",
    segment: "example.com",
  });
  assert.equal(r.passed, false);
  assert.match(r.reason, /cross-namespace/);
});

test("http family: registry.json touched → REJECT", () => {
  const r = checkPathScope({
    changedFiles: ["io.http.example.com/x.json", "registry.json"],
    family: "http",
    segment: "example.com",
  });
  assert.equal(r.passed, false);
  assert.match(r.reason, /registry\.json/);
});

test("http family with a subdomain domain segment (io.http.sub.example.com/) → pass", () => {
  // Domains may contain dots + hyphens — the http segment is a full domain.
  const r = checkPathScope({
    changedFiles: ["io.http.sub.example.com/x.json"],
    family: "http",
    segment: "sub.example.com",
  });
  assert.equal(r.passed, true);
});
