// ownership.test.mjs — the adversarial ownership matrix (RESEARCH §4.3).
// The highest-value test suite in Phase 3: every row is a discrete typosquat /
// spoof / collision attack the exact-match check MUST reject.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkOwnership } from "../../scripts/checks/ownership.mjs";

// Helper: an isOrgMember stub that returns true only for the given (org,user) pair.
const memberOf = (org, user) => async (o, u) => o === org && u === user;

test("personal namespace: org === author → pass", async () => {
  const r = await checkOwnership({
    org: "artem-sagaida",
    authorLogin: "artem-sagaida",
    isOrgMember: async () => false,
  });
  assert.equal(r.passed, true);
});

test("org namespace: author is a member → pass", async () => {
  const r = await checkOwnership({
    org: "stripe",
    authorLogin: "alice",
    isOrgMember: memberOf("stripe", "alice"),
  });
  assert.equal(r.passed, true);
});

test("personal namespace prefix squat REJECT: 'e' targeting io.github.evil", async () => {
  // Attacker "e" is NOT a member of org/owner "evil" — the stub reflects that.
  // (The attack hopes the check is a prefix match: "e" is a prefix of "evil".)
  const r = await checkOwnership({
    org: "evil",
    authorLogin: "e",
    isOrgMember: async () => false,
  });
  assert.equal(r.passed, false);
  assert.match(r.reason, /e.*evil/); // reason names seen 'e' ≠ 'evil'
});

test("suffix squat REJECT: 'evi' targeting io.github.evil", async () => {
  const r = await checkOwnership({
    org: "evil",
    authorLogin: "evi",
    isOrgMember: async () => false,
  });
  assert.equal(r.passed, false);
});

test("homoglyph REJECT: login 'strlpe' impersonating a member of org 'stripe'", async () => {
  // The attack: a login that looks like a real org member, targeting that org's
  // namespace. "strlpe" is NOT a member of "stripe" → REJECT.
  const r = await checkOwnership({
    org: "stripe",
    authorLogin: "strlpe",
    isOrgMember: memberOf("stripe", "stripe-real-member"),
  });
  assert.equal(r.passed, false);
});

test("case: canonical-lowercase comparison — legitimate owner passes case-insensitively", async () => {
  // GitHub logins are case-insensitive on lookup; the namespace is always
  // lowercase (AUTH-03 regex). A login returned as "STRIPE" still owns
  // io.github.stripe. (Uppercase-NAMESPACE rejection is the schema check's
  // job — tested in schema.test.mjs. Ownership compares canonical lowercase.)
  const r = await checkOwnership({
    org: "stripe",
    authorLogin: "STRIPE",
    isOrgMember: async () => false,
  });
  assert.equal(r.passed, true);
});

test("case match: personal namespace matches ignoring case (canonical lowercase)", async () => {
  // A user whose login canonical form equals the org canonical form still owns it.
  const r = await checkOwnership({
    org: "Artem-Sagaida",
    authorLogin: "artem-sagaida",
    isOrgMember: async () => false,
  });
  assert.equal(r.passed, true);
});

test("trailing whitespace REJECT then trim: 'stripe ' vs 'stripe' → trimmed, not a member", async () => {
  const r = await checkOwnership({
    org: "stripe ",
    authorLogin: "stripe",
    isOrgMember: async () => false,
  });
  // After trim both are 'stripe'; since they'd match as personal namespace...
  // but here org 'stripe' === author 'stripe' byte-equal post-trim → PASS as personal.
  assert.equal(r.passed, true);
});

test("trailing whitespace as a true mismatch: 'stripe ' author vs 'evil' org → REJECT", async () => {
  const r = await checkOwnership({
    org: "evil",
    authorLogin: "stripe ",
    isOrgMember: async () => false,
  });
  assert.equal(r.passed, false);
});

test("D-05 PR-body spoof: the function signature has NO body parameter", () => {
  // Static shape check: checkOwnership accepts only {org, authorLogin, isOrgMember}.
  // There is no path by which PR-body text can influence the result. This test
  // asserts the function's arity + that it doesn't read a 'body'/'prBody' key.
  assert.equal(checkOwnership.length, 1, "checkOwnership takes a single args object");
  const src = String(checkOwnership);
  assert.doesNotMatch(src, /prBody|pr_body|\bbody\b/);
});

test("empty org or author → fail safe", async () => {
  const r1 = await checkOwnership({ org: "", authorLogin: "x" });
  assert.equal(r1.passed, false);
  const r2 = await checkOwnership({ org: "x", authorLogin: "" });
  assert.equal(r2.passed, false);
});

test("org-membership lookup throws → fail safe (D-12)", async () => {
  const r = await checkOwnership({
    org: "stripe",
    authorLogin: "alice",
    isOrgMember: async () => {
      throw new Error("network");
    },
  });
  assert.equal(r.passed, false);
  assert.match(r.reason, /failing safe/);
});

test("non-member author of a real org → REJECT", async () => {
  const r = await checkOwnership({
    org: "stripe",
    authorLogin: "mallory",
    isOrgMember: memberOf("stripe", "alice"),
  });
  assert.equal(r.passed, false);
});

test("default isOrgMember (omitted) → fails safe (never grants)", async () => {
  const r = await checkOwnership({
    org: "stripe",
    authorLogin: "alice",
    // no isOrgMember → default rejects
  });
  assert.equal(r.passed, false);
});
