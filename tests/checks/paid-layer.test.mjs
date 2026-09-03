// paid-layer.test.mjs — the paid-layer gate check + the vendored pro_paths
// matcher (paid-01).
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkPaidLayer, matchesProPaths } from "../../scripts/checks/paid-layer.mjs";

const paidManifest = {
  namespace: "io.github.publisher",
  name: "bundle",
  paid: {
    provider: "polar",
    organization_id: "org-1",
    product_id: "prod-1",
    benefit_id: "ben-1",
    checkout_url: "https://buy.polar.sh/prod-1",
    price_hint: { amount: 9.99, currency: "USD", recurring: "month" },
    includes: [],
    pro_source: { type: "github", url: "https://github.com/publisher/private", path: "", ref: "main" },
    pro_paths: ["pro/**"],
  },
};

function okFetch() {
  return async () => ({ status: 200 });
}

test("free bundle (no paid block) → n/a pass, no fetch", async () => {
  let called = 0;
  const r = await checkPaidLayer({
    manifest: { namespace: "io.github.a", name: "b" },
    targetFileExistsOnMain: false,
    paidFetch: async () => {
      called += 1;
      return { status: 200 };
    },
  });
  assert.equal(r.passed, true);
  assert.match(r.reason, /n\/a/);
  assert.equal(called, 0);
});

test("paid block on a NEW namespace (no merged free publish) → blocked", async () => {
  const r = await checkPaidLayer({
    manifest: paidManifest,
    targetFileExistsOnMain: false,
    paidFetch: okFetch(),
  });
  assert.equal(r.passed, false);
  assert.match(r.reason, /at least one MERGED/);
});

test("non-Polar checkout host → blocked", async () => {
  const r = await checkPaidLayer({
    manifest: {
      ...paidManifest,
      paid: { ...paidManifest.paid, checkout_url: "https://pay.evil.example/prop" },
    },
    targetFileExistsOnMain: true,
    paidFetch: okFetch(),
  });
  assert.equal(r.passed, false);
  assert.match(r.reason, /polar checkout/i);
});

test("checkout 404 (deleted/mistyped product) → blocked with HTTP named", async () => {
  const r = await checkPaidLayer({
    manifest: paidManifest,
    targetFileExistsOnMain: true,
    paidFetch: async () => ({ status: 404 }),
  });
  assert.equal(r.passed, false);
  assert.match(r.reason, /HTTP 404/);
});

test("happy path: established bundle + resolving polar checkout → pass, honest limits stated", async () => {
  const r = await checkPaidLayer({
    manifest: paidManifest,
    targetFileExistsOnMain: true,
    paidFetch: okFetch(),
  });
  assert.equal(r.passed, true);
  assert.match(r.reason, /display-only/);
  assert.match(r.reason, /never materialized publicly/);
});

test("matchesProPaths (vendored): pro/** any depth, fail-closed at root", () => {
  assert.equal(matchesProPaths("pro/a.md", ["pro/**"]), true);
  assert.equal(matchesProPaths("pro/deep/b.md", ["pro/**"]), true);
  assert.equal(matchesProPaths("a.md", ["pro/**"]), false);
  assert.equal(matchesProPaths("processor/a.md", ["pro/**"]), false);
  assert.equal(matchesProPaths("x.md", []), false);
});
