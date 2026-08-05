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
//      GET /orgs/{org}/public_members/{author} (204 = member). The check
//      function itself never touches the network.
//
//      NOTE (audit H2): public_members only reflects members whose org
//      membership is set to public — a common privacy setting. A legitimate
//      private member will get a 404 here and be rejected, indistinguishable
//      from a non-member. This fails in the SAFE direction (no unauthorized
//      publish), so it is not a security hole; the self-serviceable fix (make
//      membership public) is surfaced in the failure comment by the caller in
//      gate-lib.mjs. Swapping to /members/{author} does not help — the App
//      installation has no elevated visibility into arbitrary third-party orgs'
//      private membership.
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

/**
 * @typedef {(recordName: string, domain: string, expectedValue: string) => Promise<boolean>} VerifyChallenge
 */

/**
 * DNS-ownership check for io.http.<domain> publish PRs (Phase 8, HTTP-02).
 *
 * THE LOAD-BEARING SECURITY INVARIANT (T-08-GATE): an io.http.* PR's ownership
 * is proven by a DNS TXT challenge, NOT org-membership. The caller injects a
 * `verifyChallenge(recordName, domain, expectedValue)` callback that re-derives
 * the deterministic token (via challengeRecordName) and queries the
 * authoritative NS (via verifyDnsChallenge). This keeps this function pure (no
 * network) and mirrors checkOwnership's isOrgMember injection pattern.
 *
 * Fail-closed (D-12 no-silent-failure): a THROWN verifyChallenge callback
 * (resolver error, NXDOMAIN) → BLOCK. A returned `false` (TXT not yet present)
 * → BLOCK. Only a returned `true` (the TXT matches) → PASS. This is the gate's
 * half of the DNS challenge — the build-time half lives in dnsVerify
 * (computeEvidence); the gate is the merge-decision half.
 *
 * The expectedValue is the deterministic `okfhub-verify=<namespace>/<name>`
 * string — the caller computes recordName via challengeRecordName so the
 * publish CLI and the gate re-derive byte-identical values (D-01 — no issuance
 * server). This function only decides pass/fail from the callback's boolean.
 *
 * @param {object} args
 * @param {string} args.domain         The <domain> from io.http.<domain> (the segment whose authoritative NS is queried).
 * @param {string} args.recordName     The deterministic _okfhub.<token8>.<domain> TXT name (caller-derived via challengeRecordName).
 * @param {string} args.expectedValue  The okfhub-verify=<namespace>/<name> TXT value the record must carry.
 * @param {VerifyChallenge} [args.verifyChallenge] Async callback returning true iff the authoritative NS serves expectedValue at recordName. Default rejects (never-true) so tests that forget to wire it fail safe.
 * @returns {Promise<{passed: boolean, reason: string}>}
 */
export async function checkDnsOwnership({ domain, recordName, expectedValue, verifyChallenge }) {
  const d = String(domain ?? "").trim();
  const rn = String(recordName ?? "").trim();
  const ev = String(expectedValue ?? "").trim();

  if (d.length === 0 || rn.length === 0 || ev.length === 0) {
    return {
      passed: false,
      reason: `ownership: empty DNS-challenge input — domain='${d}' recordName='${rn}' expectedValue='${ev}' (all required).`,
    };
  }

  const checker = verifyChallenge ?? (async () => false);
  let ok = false;
  try {
    ok = await checker(rn, d, ev);
  } catch (e) {
    // A resolver error / NXDOMAIN within the window fails SAFE — never grant
    // ownership on an unresolved DNS query (D-12 no-silent-failure, T-08-GATE
    // fail-closed). The gate's retry loop (in the caller, around the real
    // verifyDnsChallenge) bounds how long we tolerate "not yet present"; once
    // the loop exhausts, this thrown callback path is the fail-closed gate.
    const why = e instanceof Error ? e.message : String(e);
    return {
      passed: false,
      reason: `ownership: DNS challenge lookup for '${rn}' (domain '${d}') failed — failing safe (${why}).`,
    };
  }

  if (ok) {
    return {
      passed: true,
      reason: `ownership: DNS TXT challenge verified for domain '${d}' at '${rn}'.`,
    };
  }

  return {
    passed: false,
    reason: `ownership: DNS TXT challenge NOT verified for domain '${d}' — the expected TXT record at '${rn}' was not found on the authoritative NS within the verification window. Add the TXT record and re-run the gate.`,
  };
}
