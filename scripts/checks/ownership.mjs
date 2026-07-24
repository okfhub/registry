// ownership.mjs — namespace-ownership check (Phase 3, AUTH-02 / D-05 / D-06).
//
// THE LOAD-BEARING SECURITY INVARIANT (D-05): the identity used for this check
// comes ONLY from `pull_request.user.login` (passed in here as `authorLogin`).
// There is NO `prBody` / `body` parameter — a PR whose body claims a namespace
// the author doesn't own cannot pass this check, because the body is never
// read. Do not add a body parameter.
//
// Two ownership cases (D-06):
//   1. Personal namespace: the parsed <org> byte-equals the author's login.
//      (e.g. io.github.artem-sagaida/foo.json, opened by artem-sagaida.)
//   2. Org namespace: the author is a confirmed member of the org named in the
//      path. Membership is checked via an async callback the caller wires to
//      GET /orgs/{org}/members/{author} (204 = member). The check function
//      itself never touches the network.
//
// Exact-match only — NEVER prefix. The adversarial matrix in
// tests/checks/ownership.test.mjs (RESEARCH §4.3) covers prefix, suffix,
// homoglyph, case, trailing-whitespace, and PR-body-spoof attempts.

/**
 * @typedef {(org: string, user: string) => Promise<boolean>} IsOrgMember
 */

/**
 * @param {object} args
 * @param {string} args.org            The <org> segment parsed from the target path io.github.<org>/<name>.json (already trim()'d + lowercased by the caller, or pass raw — we trim here).
 * @param {string} args.authorLogin    The PR author's login, from pull_request.user.login ONLY.
 * @param {IsOrgMember} [args.isOrgMember] Async callback for org-membership lookup. Default rejects (never-members) so tests that forget to wire it fail safe.
 * @returns {Promise<{passed: boolean, reason: string}>}
 */
export async function checkOwnership({ org, authorLogin, isOrgMember }) {
  const o = String(org ?? "").trim();
  const a = String(authorLogin ?? "").trim();

  if (o.length === 0 || a.length === 0) {
    return {
      passed: false,
      reason: `ownership: empty identity — org='${o}' author='${a}' (both required).`,
    };
  }

  // Case 1: personal namespace. Byte-equal after trim. GitHub logins are case-
  // insensitive on lookup but the canonical form is lowercase; we compare the
  // canonical lowercase forms so "Stripe"/"stripe" can't slip through on case.
  if (o.toLowerCase() === a.toLowerCase()) {
    return { passed: true, reason: `ownership: personal namespace (org===author).` };
  }

  // Case 2: org namespace. Delegate membership to the caller's callback.
  const checker = isOrgMember ?? (async () => false);
  let isMember = false;
  try {
    isMember = await checker(o, a);
  } catch {
    // A failed membership lookup (network, 404, rate-limit) fails SAFE — never
    // grant ownership on an unresolved check (D-12 no-silent-failure).
    return {
      passed: false,
      reason: `ownership: org-membership lookup for '${a}' in '${o}' failed — failing safe.`,
    };
  }

  if (isMember) {
    return {
      passed: true,
      reason: `ownership: '${a}' is a member of org '${o}'.`,
    };
  }

  return {
    passed: false,
    reason: `ownership: '${a}' is neither the owner of personal namespace '${o}' nor a member of org '${o}' (exact-match only; seen='${a}' expected='${o}').`,
  };
}
