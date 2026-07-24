// path-scope.test.mjs — D-07 defense-in-depth checks.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkPathScope, namespaceOrgFromPath } from "../../scripts/checks/path-scope.mjs";

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
