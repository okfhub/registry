// rate-limit.test.mjs — D-10 hold-not-close + the three thresholds.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkRateLimit } from "../../scripts/checks/rate-limit.mjs";

const POLICY = {
  rate_limits: {
    new_namespace_per_day_per_identity: 3,
    version_update_per_day_per_identity: 20,
    registry_wide_prs_per_hour: 50,
  },
};

test("new namespace under limit → pass", () => {
  const r = checkRateLimit({
    authorLogin: "alice",
    targetFileExistsOnMain: false,
    counts: { todayByAuthor: 2, registryWideLastHour: 5 },
    policy: POLICY,
  });
  assert.equal(r.passed, true);
});

test("new namespace OVER limit → HOLD", () => {
  const r = checkRateLimit({
    authorLogin: "alice",
    targetFileExistsOnMain: false,
    counts: { todayByAuthor: 3, registryWideLastHour: 5 },
    policy: POLICY,
  });
  assert.equal(r.passed, false);
  assert.equal(r.limitHit, "new_namespace");
  assert.match(r.reason, /3/); // count
  assert.match(r.reason, /3/); // limit
});

test("version update under limit → pass", () => {
  const r = checkRateLimit({
    authorLogin: "alice",
    targetFileExistsOnMain: true,
    counts: { todayByAuthor: 15, registryWideLastHour: 5 },
    policy: POLICY,
  });
  assert.equal(r.passed, true);
});

test("version update OVER limit → HOLD", () => {
  const r = checkRateLimit({
    authorLogin: "alice",
    targetFileExistsOnMain: true,
    counts: { todayByAuthor: 20, registryWideLastHour: 5 },
    policy: POLICY,
  });
  assert.equal(r.passed, false);
  assert.equal(r.limitHit, "version_update");
});

test("circuit breaker: registry-wide over limit → HOLD", () => {
  const r = checkRateLimit({
    authorLogin: "alice",
    targetFileExistsOnMain: false,
    counts: { todayByAuthor: 1, registryWideLastHour: 51 },
    policy: POLICY,
  });
  assert.equal(r.passed, false);
  assert.equal(r.limitHit, "circuit_breaker");
});

test("circuit breaker takes precedence over per-identity (both exceeded)", () => {
  const r = checkRateLimit({
    authorLogin: "alice",
    targetFileExistsOnMain: false,
    counts: { todayByAuthor: 10, registryWideLastHour: 60 },
    policy: POLICY,
  });
  assert.equal(r.passed, false);
  assert.equal(r.limitHit, "circuit_breaker");
});

test("D-10 hold-not-close: return shape NEVER has shouldClose=true", () => {
  // Run both pass and fail outcomes; none may carry shouldClose:true.
  const pass = checkRateLimit({
    authorLogin: "a",
    targetFileExistsOnMain: false,
    counts: { todayByAuthor: 0, registryWideLastHour: 0 },
    policy: POLICY,
  });
  const fail = checkRateLimit({
    authorLogin: "a",
    targetFileExistsOnMain: false,
    counts: { todayByAuthor: 99, registryWideLastHour: 99 },
    policy: POLICY,
  });
  assert.equal(pass.shouldClose ?? false, false);
  assert.equal(fail.shouldClose ?? false, false);
  assert.equal("shouldClose" in pass, false, "shouldClose key absent on pass");
  assert.equal("shouldClose" in fail, false, "shouldClose key absent on fail");
});

test("missing policy thresholds → treated as Infinity (never holds on absent config)", () => {
  const r = checkRateLimit({
    authorLogin: "a",
    targetFileExistsOnMain: false,
    counts: { todayByAuthor: 1000, registryWideLastHour: 1000 },
    policy: { rate_limits: {} },
  });
  // No thresholds set → no limits → pass (degrades open, by design — the
  // policy file is the source of truth; an empty policy means no limits).
  assert.equal(r.passed, true);
});
