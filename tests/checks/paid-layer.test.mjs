// paid-layer.test.mjs — the paid-layer gate check (paid-01, whole-bundle
// model: a paid bundle's source IS the private repo; the gate never fetches it).
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkPaidLayer } from "../../scripts/checks/paid-layer.mjs";

const paidManifest = {
  namespace: "io.github.publisher",
  name: "bundle",
  source: { type: "github", url: "https://github.com/publisher/private", path: "", ref: "main" },
  paid: {
    provider: "polar",
    organization_id: "org-1",
    product_id: "prod-1",
    benefit_id: "ben-1",
    checkout_url: "https://buy.polar.sh/prod-1",
    price_hint: { amount: 9.99, currency: "USD", recurring: "month" },
    includes: [],
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

test("paid bundle as a FIRST listing → identity stage passes (no free-first rule)", async () => {
  const r = await checkPaidLayer({
    manifest: paidManifest,
    targetFileExistsOnMain: false,
    paidFetch: okFetch(),
  });
  assert.equal(r.passed, true);
  assert.match(r.reason, /declared, not evaluated/);
});

test("paid bundle with a non-github source → blocked (no gateway fetch path)", async () => {
  const r = await checkPaidLayer({
    manifest: {
      ...paidManifest,
      source: { type: "http", url: "https://example.com/b.tar.gz", path: "", ref: "main" },
    },
    targetFileExistsOnMain: true,
    paidFetch: okFetch(),
  });
  assert.equal(r.passed, false);
  assert.match(r.reason, /must be a github repo/);
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
  assert.match(r.reason, /declared, not evaluated/);
});
