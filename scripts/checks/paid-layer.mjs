// paid-layer.mjs — the paid-layer gate check (paid-01, whole-bundle model).
//
// Runs inside evaluatePullRequest AFTER rate-limit, ONLY when the manifest
// declares a `paid` block (free bundles short-circuit to n/a). A paid bundle
// is a bundle whose source is a PRIVATE repo — the registry never fetches it.
// The gate enforces the rules that make such a listing trustworthy WITHOUT
// any payment plumbing in okfhub:
//
//   1. GITHUB SOURCE — the okfhub gateway fetches private repos via its
//      GitHub App installation; a paid bundle must therefore declare a
//      `github` source (private repos on other hosts have no fetch path).
//   2. POLAR CHECKOUT INTEGRITY — checkout_url must point at a polar.sh host
//      (buy.polar.sh / polar.sh / www / sandbox) AND resolve. The gate never
//      touches money; this only pins that the "Buy on Polar" link on the
//      bundle page is the publisher's real Polar checkout, not an arbitrary URL.
//
// NO free-first rule: a publisher may ship a paid bundle as their FIRST
// listing (no required free sibling). HONEST LIMITS (stated in the check's
// pass reason, which lands in the merge comment): the gate does NOT verify
// price_hint against the live Polar page (Polar product pages are
// client-rendered — a reliable scrape needs a dedicated fetcher; until then
// price_hint is display-only, verified by review), and it never looks inside
// the private source — the content is "declared, not evaluated". The
// paid_add_or_change_per_day_per_identity policy key is enforced by REVIEW,
// not by this check — the policy file marks it as such.

const POLAR_CHECKOUT_HOSTS = new Set([
  "polar.sh",
  "www.polar.sh",
  "buy.polar.sh",
  "sandbox.polar.sh", // the sandbox checkout — allowed so test publishes flow
  "api.polar.sh", // Polar API checkout-link redirect endpoint (prod)
  "sandbox-api.polar.sh", // Polar API checkout-link redirect endpoint (sandbox)
]);

/**
 * @param {object} args
 * @param {object} args.manifest - the validated manifest JSON
 * @param {boolean} args.targetFileExistsOnMain - does <ns>/<name>.json exist on main?
 * @param {typeof fetch} [args.paidFetch] - injectable fetch (tests); default global
 * @returns {Promise<{passed: boolean, reason: string}>}
 */
export async function checkPaidLayer({ manifest, targetFileExistsOnMain, paidFetch }) {
  const paid = manifest?.paid;
  if (!paid) {
    return { passed: true, reason: "paid-layer: n/a (free bundle)." };
  }

  // 1) Github source — the gateway's only private-repo fetch path.
  if (manifest.source?.type !== "github") {
    return {
      passed: false,
      reason:
        "paid-layer: a paid bundle's source must be a github repo (private) — " +
        "the okfhub gateway fetches it via its GitHub App installation. " +
        `Declared source type: '${manifest.source?.type}'.`,
    };
  }
  // The old free-first identity rule is GONE: a paid bundle may be a
  // publisher's first listing. (targetFileExistsOnMain is accepted for
  // interface compatibility and intentionally unused.)

  // 2) checkout_url host allowlist.
  let host;
  try {
    host = new URL(paid.checkout_url).hostname.toLowerCase();
  } catch {
    return {
      passed: false,
      reason: `paid-layer: checkout_url '${paid.checkout_url}' is not a valid URL. (Schema should have caught this — investigate.)`,
    };
  }
  if (!POLAR_CHECKOUT_HOSTS.has(host)) {
    return {
      passed: false,
      reason:
        `paid-layer: checkout_url must be a Polar checkout (host "${host}" is not allowed). ` +
        `Allowed hosts: ${[...POLAR_CHECKOUT_HOSTS].join(", ")}.`,
    };
  }

  // 3) checkout_url resolves. A 4xx Polar page means the product was deleted
  // or the link is wrong — block with an actionable reason.
  const f = paidFetch ?? fetch;
  let status;
  try {
    const res = await f(paid.checkout_url, { method: "GET", redirect: "follow" });
    status = res.status;
  } catch (e) {
    return {
      passed: false,
      reason: `paid-layer: could not reach ${paid.checkout_url} (${e instanceof Error ? e.message : String(e)}). Re-run the check when Polar is reachable.`,
    };
  }
  if (status >= 400) {
    return {
      passed: false,
      reason: `paid-layer: ${paid.checkout_url} returned HTTP ${status}. Fix the checkout link (deleted or mistyped Polar product?) and re-submit.`,
    };
  }

  return {
    passed: true,
    reason:
      `paid-layer: declared (provider ${paid.provider}, product ${paid.product_id}); checkout resolves on ${host}; ` +
      "source is private — declared, not evaluated, never fetched by the registry. " +
      "Note: price_hint is display-only — the live price is on the Polar page (verified by review, not by this gate).",
  };
}
