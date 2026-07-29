// rate-limit.mjs — rate-limit check (Phase 3, D-10).
//
// Anti-spam. Per-identity limits + a registry-wide circuit breaker, read from
// registry-policy.json (the tunability seam — thresholds are NOT hardcoded).
//
// HARD RULE (D-10): rate-limit HOLDS a PR out of auto-merge (and the gate posts
// a comment naming the limit, count, and reset window). It NEVER auto-closes
// the PR. The return shape therefore has NO `shouldClose` field — it is always
// false/absent. A maintainer reviews held PRs manually.
//
// Two per-identity thresholds, selected by whether the target manifest already
// exists on main:
//   - new namespace bundle  (targetFileExistsOnMain=false): new_namespace_per_day_per_identity (3/day)
//   - version update        (targetFileExistsOnMain=true):  version_update_per_day_per_identity (20/day)
// Plus a registry-wide circuit breaker: registry_wide_prs_per_hour (50/hr).

/**
 * @param {object} args
 * @param {string} args.authorLogin
 * @param {boolean} args.targetFileExistsOnMain  Selects new-namespace vs version-update threshold.
 * @param {{todayByAuthor: number, registryWideLastHour: number}} args.counts
 * @param {object} args.policy  Parsed registry-policy.json: { rate_limits: { new_namespace_per_day_per_identity, version_update_per_day_per_identity, registry_wide_prs_per_hour } }
 * @returns {{passed: boolean, reason: string, limitHit: string | null}}
 */
export function checkRateLimit({
  authorLogin,
  targetFileExistsOnMain,
  counts,
  policy,
}) {
  const rl = (policy && policy.rate_limits) || {};
  const today = counts?.todayByAuthor ?? 0;
  const registryWide = counts?.registryWideLastHour ?? 0;

  // Circuit breaker first — if the whole registry is being flooded, hold
  // everyone regardless of per-identity standing.
  const circuit = rl.registry_wide_prs_per_hour ?? Infinity;
  if (registryWide >= circuit) {
    return {
      passed: false,
      reason: `rate-limit (circuit_breaker): registry-wide PR count this hour is ${registryWide} >= limit ${circuit}. PR held (not closed) — a maintainer will review.`,
      limitHit: "circuit_breaker",
    };
  }

  const isNew = !targetFileExistsOnMain;
  const perIdentityLimit = isNew
    ? (rl.new_namespace_per_day_per_identity ?? Infinity)
    : (rl.version_update_per_day_per_identity ?? Infinity);
  const kind = isNew ? "new_namespace" : "version_update";

  if (today >= perIdentityLimit) {
    return {
      passed: false,
      reason: `rate-limit (${kind}): '${authorLogin}' has ${today} PR(s) today >= limit ${perIdentityLimit} for ${kind}. PR held (not closed); resets at 00:00 UTC. A maintainer will review.`,
      limitHit: kind,
    };
  }

  return {
    passed: true,
    reason: `rate-limit: '${authorLogin}' at ${today}/${perIdentityLimit} (${kind}); registry-wide ${registryWide}/${circuit}. Under limits.`,
    limitHit: null,
  };
}
