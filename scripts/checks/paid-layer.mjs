// paid-layer.mjs — the paid-layer gate check (paid-01, POLAR-PAYWALL-PLAN §D).
//
// Runs inside evaluatePullRequest AFTER rate-limit, ONLY when the manifest
// declares a `paid` block (free bundles short-circuit to n/a). Enforces the
// two rules that make a paid listing trustworthy WITHOUT any payment plumbing
// in okfhub:
//
//   1. ESTABLISHED IDENTITY — the bundle must already exist on main (a merged
//      free publish). A brand-new namespace cannot ship a paid layer on its
//      first PR: the free map comes first, the paid territory second.
//   2. POLAR CHECKOUT INTEGRITY — checkout_url must point at a polar.sh host
//      (buy.polar.sh / polar.sh / www / sandbox) AND resolve. The gate never
//      touches money; this only pins that the "Buy on Polar" link on the
//      bundle page is the publisher's real Polar checkout, not an arbitrary URL.
//
// HONEST LIMITS (stated in the check's pass reason, which lands in the merge
// comment): the gate does NOT verify price_hint against the live Polar page
// (Polar product pages are client-rendered — a reliable scrape needs a
// dedicated fetcher; until then price_hint is display-only, verified by
// review). The paid_add_or_change_per_day_per_identity policy key is enforced
// by REVIEW, not by this check — the policy file marks it as such.

const POLAR_CHECKOUT_HOSTS = new Set([
  "polar.sh",
  "www.polar.sh",
  "buy.polar.sh",
  "sandbox.polar.sh", // the sandbox checkout — allowed so test publishes flow
]);

/**
 * paid-01 — does `relPath` (POSIX, relative to the bundle root) fall inside
 * the gated `paid.pro_paths` set? VENDORED from okfhub-cli/src/lib/installer.ts
 * (the CLI is the source of truth; the website's lib/mcp/pro.ts carries the
 * same vendored twin). Keep in sync across the three copies.
 * Patterns: "pro/**" (any depth), "dir/*" (one level), exact file path.
 *
 * @param {string} relPath
 * @param {string[]} patterns
 * @returns {boolean}
 */
export function matchesProPaths(relPath, patterns) {
  const norm = relPath.replace(/\\/g, "/");
  return patterns.some((raw) => {
    const pat = raw.replace(/\\/g, "/").replace(/^\.\//, "");
    if (pat.endsWith("/**")) {
      const prefix = pat.slice(0, -3);
      return prefix === "" || norm.startsWith(prefix + "/");
    }
    if (pat.endsWith("/*")) {
      const prefix = pat.slice(0, -2);
      if (!norm.startsWith(prefix + "/")) return false;
      return !norm.slice(prefix.length + 1).includes("/");
    }
    return norm === pat;
  });
}

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

  // 1) Established identity: the free map ships before the paid territory.
  if (!targetFileExistsOnMain) {
    return {
      passed: false,
      reason:
        "paid-layer: a bundle must have at least one MERGED (free) publish before adding a paid layer. " +
        "Publish the free bundle first, then add the `paid` block in a follow-up PR.",
    };
  }

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
      `paid-layer: declared (provider ${paid.provider}, product ${paid.product_id}); checkout resolves on ${host}. ` +
      "Note: price_hint is display-only — the live price is on the Polar page (verified by review, not by this gate); " +
      "pro_source is fetched only by the okfhub gateway, never materialized publicly.",
  };
}
