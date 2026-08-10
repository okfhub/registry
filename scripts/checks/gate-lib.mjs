// gate-lib.mjs — shared gate logic for both the check + merge entry points.
//
// This module is the SINGLE source of truth for the four publish-PR checks
// (schema → path-scope → ownership → rate-limit) and the merge call. Both
// gate-check.mjs (on: pull_request — no secrets) and gate-merge.mjs
// (on: workflow_run — has the App secret) import from here.
//
// WHY THE SPLIT EXISTS: a workflow triggered by `pull_request` from a FORK
// receives only the default GITHUB_TOKEN — repo secrets AND variables are
// withheld (docs: "secrets are not passed to the runner when a workflow is
// triggered from a forked repository"). The merge needs the App private key
// (secret OKFHUB_APP_PRIVATE_KEY) to mint an installation token that can merge
// AND trigger the downstream build-registry.yml. So the checks run in the
// fork-PR context (GITHUB_TOKEN only), and the merge runs in a follow-up
// workflow_run (default-branch context, full secrets). GitHub recommends this
// `workflow_run` pattern specifically for fork-PR + secrets.
//
// SECURITY: workflow_run checks out trusted code from the default branch, so
// the merge step always runs THIS file (not PR-authored code). The gate never
// executes anything from the PR — it fetches the manifest JSON via the API and
// validates it with zod. Re-running evaluatePullRequest in the merge step is
// defense-in-depth (the PR head may have changed between the two runs).
//
// IDENTITY INVARIANT (D-05): the author login comes from
// `pull_request.user.login` in the event payload ONLY — never from the PR body.
// The ownership check's signature takes authorLogin as a parameter; there is no
// body parameter anywhere in this file.
//
// Env contract:
//   GITHUB_API_URL       — https://api.github.com (set by Actions, defaulted)

import { readFile } from "node:fs/promises";

import { checkSchema } from "./schema.mjs";
import { checkPathScope, namespaceOrgFromPath, namespaceFamilyFromPath } from "./path-scope.mjs";
import { checkOwnership, checkDnsOwnership } from "./ownership.mjs";
import { checkRateLimit } from "./rate-limit.mjs";
import { checkStructure } from "./structure.mjs";
import { challengeRecordName, verifyDnsChallenge } from "./dns-verify.mjs";

const API = process.env.GITHUB_API_URL || "https://api.github.com";
const POLICY_PATH = process.env.REGISTRY_POLICY_PATH || "registry-policy.json";

// DNS-ownership propagation-retry loop (Phase 8, user-driven addition). When a
// publisher adds the TXT record and immediately re-runs the gate, the record
// may not yet have propagated to the authoritative NS. The gate retries every
// DNS_RETRY_INTERVAL_MS (5s) for up to DNS_RETRY_BUDGET_MS (60s) before
// declaring failure. This is INSIDE the check (still a one-shot CI run), NOT a
// separate polling server — bounded (60s ceiling) + fixed interval (5s), NOT
// configurable in this commit (avoid scope creep). Honors D-01 (no issuance
// server) and addresses the enforcement-confidence question: a publisher who
// adds the TXT and re-runs the gate within ~60s still passes without a spurious
// red check.
const DNS_RETRY_INTERVAL_MS = 5 * 1000;
const DNS_RETRY_BUDGET_MS = 60 * 1000;

/** Build a gh() fetcher bound to a specific token. Each entry point passes its
 *  own token (GITHUB_TOKEN for check, App installation token for merge). */
export function makeGh(token) {
  function authHeaders(extra = {}) {
    const h = {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...extra,
    };
    if (token) {
      h.Authorization = `token ${token}`;
    }
    return h;
  }
  async function gh(path, init = {}) {
    const url = path.startsWith("http") ? path : `${API}${path}`;
    return fetch(url, { ...init, headers: { ...authHeaders(), ...(init.headers || {}) } });
  }
  return { gh, authHeaders };
}

/** Post a comment on the PR (D-12 — no silent failures). Needs a token with
 *  pull-requests:write. The check step's GITHUB_TOKEN does NOT have this on a
 *  fork PR, so commenting is done by the merge step (App token). */
export async function postComment(gh, repo, prNumber, body) {
  await gh(`/repos/${repo}/issues/${prNumber}/comments`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ body }),
  });
}

/** Neutralize attacker-controlled strings before they're interpolated into a
 *  PR comment (audit M3). Manifest fields, namespace paths, and changed-file
 *  names all come from a hostile PR and could otherwise inject Markdown
 *  formatting, images/links, or (much less likely post-2020) workflow-command
 *  directives via the comment body.
 *
 *  - Backslash-escapes the Markdown-active characters so they render literally
 *    instead of formatting (` * _ [ ] # < > \).
 *  - Collapses newlines to single spaces, defeating any `::`-prefixed line
 *    that could be misread as a workflow command in an echo'd log.
 *  This is display-only hygiene; the security checks themselves never rely on
 *  comment text (D-05 identity is pull_request.user.login, not body/fields). */
export function sanitizeForComment(s) {
  return String(s ?? "")
    .replace(/[\\`*_\[\]#<>]/g, (ch) => `\\${ch}`)
    .replace(/[\r\n]+/g, " ");
}

/** Fetch the full list of changed files for a PR (paginated — uses per_page=100). */
async function fetchChangedFiles(gh, repo, prNumber) {
  const res = await gh(`/repos/${repo}/pulls/${prNumber}/files?per_page=100`);
  if (!res.ok) {
    throw new Error(`pulls/files HTTP ${res.status}`);
  }
  const files = await res.json();
  return files.map((f) => f.filename);
}

/** Does the author have push permission on this repo? (infra-PR gate.)
 *
 *  Uses GET /repos/{repo}/collaborators/{username}/permission, which returns
 *  `{ permission, user: { ..., permissions: { admin, maintain, push, triage, pull } }, role_name }`.
 *  The top-level `permission` is the canonical role string
 *  ("admin"|"maintain"|"write"|"triage"|"read"|"none"). We treat
 *  admin/maintain/write/triage as "maintainer" (can push), read/none as not.
 *
 *  BUGFIX: the previous implementation read `j.permissions.push` — but the
 *  `permissions` object is nested inside `user`, not at the top level. So
 *  `j.permissions` was always undefined, and isMaintainer returned false for
 *  EVERY author (including admins). This silently broke the infra-PR gate path
 *  from the day it was introduced (Phase 3, bbf48aa); it was never exercised
 *  under the hardened main-protection ruleset (2026-08-04) because all prior
 *  infra commits landed by direct push before the ruleset hardened.
 *
 *  Fail-closed: a non-2xx response is treated as "not a maintainer" so the
 *  infra PR stays red rather than silently auto-approving on an API hiccup. */
async function isMaintainer(gh, repo, authorLogin) {
  const res = await gh(`/repos/${repo}/collaborators/${encodeURIComponent(authorLogin)}/permission`);
  if (!res.ok) return false;
  const j = await res.json().catch(() => ({}));
  const role = j?.permission; // "admin"|"maintain"|"write"|"triage"|"read"|"none"
  return role === "admin" || role === "maintain" || role === "write" || role === "triage";
}

/** Fetch the manifest JSON a PR publishes (from the head branch), if any. */
async function fetchManifestAt(gh, repo, prNumber, filePath) {
  const prRes = await gh(`/repos/${repo}/pulls/${prNumber}`);
  if (!prRes.ok) throw new Error(`pulls HTTP ${prRes.status}`);
  const pr = await prRes.json();
  const headSha = pr.head?.sha;
  const cRes = await gh(`/repos/${repo}/contents/${filePath}?ref=${headSha}`);
  if (!cRes.ok) return null; // file not present at head (e.g. a deletion PR)
  const c = await cRes.json();
  if (c.encoding !== "base64" || typeof c.content !== "string") return null;
  const text = Buffer.from(c.content, "base64").toString("utf8");
  return JSON.parse(text);
}

/** Does the target manifest file already exist on main (version-update vs new)? */
async function targetFileExistsOnMain(gh, repo, filePath) {
  const res = await gh(`/repos/${repo}/contents/${filePath}?ref=main`);
  return res.ok;
}

/** Count the author's PRs to this repo today (per-identity rate-limit input). */
async function countAuthorPrsToday(gh, repo, authorLogin) {
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD UTC
  const q = `repo:${repo}+type:pr+author:${authorLogin}+created:>=${today}`;
  const res = await gh(`/search/issues?q=${encodeURIComponent(q)}&per_page=1`);
  if (!res.ok) return 0; // degrade-open on search failure (logged elsewhere)
  const j = await res.json();
  return j.total_count ?? 0;
}

/** Count ALL PRs to this repo in the last hour (circuit-breaker input). */
async function countRegistryPrsLastHour(gh, repo) {
  const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const q = `repo:${repo}+type:pr+created:>=${since}`;
  const res = await gh(`/search/issues?q=${encodeURIComponent(q)}&per_page=1`);
  if (!res.ok) return 0;
  const j = await res.json();
  return j.total_count ?? 0;
}

/**
 * Verify the DNS TXT challenge against the authoritative NS, retrying on
 * failure for up to DNS_RETRY_BUDGET_MS at DNS_RETRY_INTERVAL_MS intervals
 * (Phase 8 propagation-retry loop — user-driven addition).
 *
 * The retry is INSIDE the check (still a one-shot CI run): a publisher who adds
 * the TXT record and immediately re-runs the gate, before DNS propagation
 * completes, gets up to ~60s of retries rather than a spurious red check. Once
 * the budget is exhausted (TXT still not present) or verifyDnsChallenge throws
 * (resolver error), the loop returns false / rethrows so checkDnsOwnership
 * fails-closed. NXDOMAIN within the window is a transient "not yet present"
 * signal that verifyDnsChallenge swallows → false (retry); a thrown resolver
 * error is a hard "fail-closed" signal (rethrow).
 *
 * Tests override the interval/budget via opts to keep the suite fast
 * ({ dnsRetryInterval: 0, dnsRetryBudget: 0 } → a single immediate shot).
 *
 * @param {string} recordName
 * @param {string} domain
 * @param {string} expectedValue
 * @param {object} [opts] - { resolver, dnsRetryInterval, dnsRetryBudget }
 * @returns {Promise<boolean>}
 */
async function verifyDnsWithRetry(recordName, domain, expectedValue, opts = {}) {
  const interval = opts.dnsRetryInterval ?? DNS_RETRY_INTERVAL_MS;
  const budget = opts.dnsRetryBudget ?? DNS_RETRY_BUDGET_MS;
  const start = Date.now();
  for (;;) {
    // verifyDnsChallenge returns false on NXDOMAIN (record not yet present) —
    // retryable within the budget. A thrown error (resolver failure) rethrows so
    // checkDnsOwnership fail-closes (T-08-GATE).
    const ok = await verifyDnsChallenge(recordName, domain, expectedValue, opts);
    if (ok) return true;
    if (Date.now() - start >= budget) return false; // budget exhausted → not present
    await sleep(interval);
  }
}

function sleep(ms) {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Evaluate a publish PR against all four checks. PURE-ish: fetches PR state via
 * the given gh() fetcher, runs the checks, and returns a structured result.
 * Never calls process.exit, never posts comments, never merges — the caller
 * decides what to do with the result.
 *
 * Phase 8 generalizes the manifest detection + ownership dispatch to a
 * namespace-family model: io.github.* → org-membership (unchanged);
 * io.http.* → DNS-ownership (re-derived token + authoritative-NS verify with a
 * propagation-retry loop).
 *
 * @param {object} gh - fetcher from makeGh(token)
 * @param {string} repo - "okfhub/registry"
 * @param {object} pr - the pull_request object from the event payload
 * @param {object} [opts] - injection seam for tests: { verifyDns (override the
 *   authoritative-NS verifier), resolver (threaded to verifyDnsChallenge),
 *   dnsRetryInterval, dnsRetryBudget }
 * @returns {Promise<{passed: boolean, reason: string|null, manifestPath: string|null, org: string|null, authorLogin: string, headSha: string, prNumber: number, infra?: boolean}>}
 */
export async function evaluatePullRequest(gh, repo, pr, opts = {}) {
  const prNumber = pr.number;
  // D-05: identity from pull_request.user.login ONLY. Never pr.body.
  const authorLogin = pr.user?.login;
  const headSha = pr.head?.sha;
  if (!authorLogin || !headSha) {
    return {
      passed: false,
      reason:
        "⚠️ merge-gate: could not determine PR author login or head SHA from the event payload — refusing to merge (fail-closed).",
      manifestPath: null,
      org: null,
      authorLogin: authorLogin || null,
      headSha: headSha || null,
      prNumber,
    };
  }

  const changedFiles = await fetchChangedFiles(gh, repo, prNumber);
  // The target manifest = the io.<family>.<segment>/<name>.json the PR publishes.
  // Phase 8 widens from io.github.* to io.(github|http).* (http segment is a
  // domain, so it allows dots + hyphens).
  const manifestPath = changedFiles.find((f) => /^io\.(github|http)\.[a-z0-9.-]+\//.test(f));
  if (!manifestPath) {
    // INFRA PR (no manifest): maintenance changes to scripts/, tests/, .github/,
    // lib/, docs, etc. These cannot be evaluated by the publish checks (there is
    // no namespace to own / no source to clone). They pass the gate ONLY when the
    // PR author is a repo collaborator with push permission — i.e. a trusted
    // maintainer (admin/maintain/write/triage). A fork/external author's infra PR
    // stays RED (existing behavior), so no privilege-escalation surface opens:
    // a fork can't auto-merge code into scripts/ or .github/workflows/.
    //
    // The result carries `infra: true` so gate-merge.mjs knows to post a comment
    // and STOP — it does NOT auto-merge infra PRs (a human merges those). This
    // keeps the publish-only auto-merge contract intact while letting the
    // required-status `check` go green for maintainer infra PRs.
    const infra = await isMaintainer(gh, repo, authorLogin);
    if (infra) {
      return {
        passed: true,
        infra: true,
        reason: null,
        manifestPath: null,
        org: null,
        authorLogin,
        headSha,
        prNumber,
      };
    }
    return {
      passed: false,
      reason: `⚠️ merge-gate: no \`io.github.<org>/<name>.json\` manifest found among the changed files (${changedFiles.map(sanitizeForComment).join(", ")}). Publish PRs must add exactly one manifest under \`io.github.*\`; infra PRs (no manifest) must come from a collaborator with write permission.`,
      infra: false,
      manifestPath: null,
      org: null,
      authorLogin,
      headSha,
      prNumber,
    };
  }
  const org = namespaceOrgFromPath(manifestPath);
  // Phase 8 namespace-family detection. For io.github.*, family=github + the
  // segment is the org (org === segment, backward compat). For io.http.*, the
  // segment is the domain; the org-membership check does not apply — a DNS
  // challenge proves ownership instead.
  const { family, segment } = namespaceFamilyFromPath(manifestPath);
  const fam = family ?? "github";
  const domain = fam === "http" ? segment : null;

  // 1) SCHEMA — fetch the manifest at head + validate (AUTH-03 enforced here).
  const manifestJson = await fetchManifestAt(gh, repo, prNumber, manifestPath);
  if (manifestJson === null) {
    return {
      passed: false,
      reason: `⚠️ merge-gate: could not read manifest \`${sanitizeForComment(manifestPath)}\` at the PR head — refusing to merge.`,
      manifestPath,
      org,
      authorLogin,
      headSha,
      prNumber,
    };
  }
  const schemaResult = checkSchema(manifestJson);
  if (!schemaResult.passed) {
    return {
      passed: false,
      reason: `🚫 **merge-gate blocked**\n\n${sanitizeForComment(schemaResult.reason)}`,
      manifestPath,
      org,
      authorLogin,
      headSha,
      prNumber,
    };
  }

  // 1b) NAMESPACE FIELD/PATH CONSISTENCY (defense-in-depth, found by audit).
  // The ownership check derives the org from the manifest's PATH (org parsed
  // from io.github.<org>/<name>.json). But build-registry aggregates using the
  // manifest's namespace FIELD. Without this check, an attacker who owns
  // io.github.alice/ could publish io.github.alice/bitcoin.json with a manifest
  // whose namespace FIELD is io.github.google — passing ownership (path=alice)
  // + schema (field matches the io.github.* regex) but polluting registry.json
  // with a duplicate {namespace: io.github.google, name: bitcoin}. Install is
  // not compromised (fetchManifest resolves via the raw PATH + an integrity
  // check), but the index/listing/search would show the attacker's entry.
  // Fix: require the manifest's declared namespace to match the path it lives
  // at, byte-for-byte (both canonical lowercase). The CLI keeps these
  // consistent by construction (publish.ts derives the path FROM the field);
  // this blocks hand-crafted PRs.
  const declaredNamespace = manifestJson.namespace;
  // Per-family namespace field/path consistency (T-08-CONSISTENCY). For github,
  // require declaredNamespace === io.github.<org>. For http, require
  // declaredNamespace === io.http.<domain>. Both canonical-lowercase. A
  // mismatch indicates a hand-crafted PR attempting namespace impersonation in
  // the index (the CLI derives path from field by construction).
  const expectedDeclaredNamespace =
    fam === "http" ? `io.http.${domain}` : `io.github.${org}`;
  if (
    typeof declaredNamespace !== "string" ||
    declaredNamespace.toLowerCase() !== expectedDeclaredNamespace
  ) {
    const expectedPathPrefix = fam === "http" ? `io.http.${domain}` : `io.github.${org}`;
    return {
      passed: false,
      reason: `🚫 **merge-gate blocked**\n\nnamespace: manifest declares \`${sanitizeForComment(declaredNamespace)}\` but lives at path \`${expectedPathPrefix}/\` — the declared namespace must match the file's path. The CLI derives the path from the namespace by construction; a mismatch indicates a hand-crafted PR attempting namespace impersonation in the index.`,
      manifestPath,
      org,
      authorLogin,
      headSha,
      prNumber,
    };
  }

  // 2) PATH-SCOPE (D-07). Pass the family + segment so the per-family prefix
  // (io.github.<org>/ or io.http.<domain>/) is enforced.
  const pathResult = checkPathScope({ changedFiles, org, family: fam, segment });
  if (!pathResult.passed) {
    return {
      passed: false,
      reason: `🚫 **merge-gate blocked**\n\n${pathResult.reason}`,
      manifestPath,
      org,
      authorLogin,
      headSha,
      prNumber,
    };
  }

  // 3) OWNERSHIP — branch on namespace family (Phase 8).
  //    io.github.* → org-membership (AUTH-02 / D-05 / D-06, UNCHANGED).
  //    io.http.*   → DNS-ownership: re-derive the deterministic token via
  //                  challengeRecordName + query the authoritative NS via
  //                  verifyDnsChallenge (with the propagation-retry loop). Fail
  //                  closed (block) on NXDOMAIN within the window or any
  //                  resolver error (T-08-GATE). The expectedValue is the
  //                  deterministic okfhub-verify=<namespace>/<name> string —
  //                  the publish CLI computes the same token, so no issuance
  //                  server (D-01).
  let ownershipResult;
  if (fam === "http" && domain) {
    const recordName = challengeRecordName(
      manifestJson.namespace,
      manifestJson.name,
      manifestJson.source?.url ?? "",
      domain,
    );
    const expectedValue = `okfhub-verify=${manifestJson.namespace}/${manifestJson.name}`;
    // The verifyChallenge callback re-derives + queries the authoritative NS.
    // Tests inject opts.verifyDns to avoid live DNS; production uses the real
    // verifyDnsChallenge wrapped in the propagation-retry loop.
    const verifyChallenge =
      opts.verifyDns ??
      (async (rn, dom, ev) => verifyDnsWithRetry(rn, dom, ev, opts));
    ownershipResult = await checkDnsOwnership({
      domain,
      recordName,
      expectedValue,
      verifyChallenge,
    });
  } else {
    ownershipResult = await checkOwnership({
      org,
      authorLogin,
      isOrgMember: async (o, u) => {
        // 204 = member; 404/302/others = not a member. Fail-closed on non-2xx.
        // Uses the public_members endpoint (no extra scope needed).
        const r = await gh(`/orgs/${o}/public_members/${u}`);
        return r.status === 204;
      },
    });
  }
  if (!ownershipResult.passed) {
    // Audit H2: when ownership fails on the ORG-membership path (org ≠ author),
    // the public_members endpoint can't distinguish a private member from a
    // non-member. Append the self-serviceable fix so a legitimate but
    // private-member publisher isn't left guessing. The check function itself
    // stays generic; only the posted comment carries this product hint.
    // Phase 8: this hint is github-only (the http path has no org/membership).
    const orgMembershipHint =
      fam === "github" &&
      org &&
      org.toLowerCase() !== authorLogin.toLowerCase() &&
      /member of org/.test(ownershipResult.reason)
        ? `\n\nℹ️ Org-namespace publishing checks PUBLIC org membership only. If you are a member of \`${org}\` but your membership is private, the gate can't see it — either make it public (https://github.com/orgs/${org}/people → "Publicize") or publish under your personal namespace \`io.github.${authorLogin.toLowerCase()}\`.`
        : "";
    return {
      passed: false,
      reason: `🚫 **merge-gate blocked**\n\n${ownershipResult.reason}${orgMembershipHint}`,
      manifestPath,
      org,
      authorLogin,
      headSha,
      prNumber,
    };
  }

  // 4) RATE-LIMIT (D-10). Read thresholds from registry-policy.json.
  let policy = {};
  try {
    policy = JSON.parse(await readFile(POLICY_PATH, "utf8"));
  } catch (e) {
    console.error(`merge-gate: WARNING — could not read ${POLICY_PATH} (${e.message}); applying no limits.`);
  }
  const exists = await targetFileExistsOnMain(gh, repo, manifestPath);
  const todayByAuthor = await countAuthorPrsToday(gh, repo, authorLogin);
  const registryWideLastHour = await countRegistryPrsLastHour(gh, repo);
  const rateResult = checkRateLimit({
    authorLogin,
    targetFileExistsOnMain: exists,
    counts: { todayByAuthor, registryWideLastHour },
    policy,
  });
  if (!rateResult.passed) {
    return {
      passed: false,
      // D-10: HOLD, never close. The comment names the limit + count + reset.
      reason: `⏸️ **merge-gate held (rate-limit, not closed)**\n\n${rateResult.reason}`,
      manifestPath,
      org,
      authorLogin,
      headSha,
      prNumber,
    };
  }

  // 5) STRUCTURAL IDENTITY (D-02 / D-08, VAL-02). Runs ONLY in the check half,
  //    which cloned the PR's source repo and set STRUCTURE_BUNDLE_DIR. The merge
  //    half re-runs evaluatePullRequest WITHOUT it (the registry-scoped App
  //    token cannot clone arbitrary github.com/<owner>/<repo> sources — T-04-SCOPE),
  //    so it TRUSTS this check's success conclusion (D-02 critical invariant).
  //    When the env var is unset, skip #5 (do not fail) — defense-in-depth for
  //    checks 1-4 still runs in both halves.
  if (process.env.STRUCTURE_BUNDLE_DIR) {
    const structureResult = await checkStructure({
      manifest: manifestJson,
      bundleDir: process.env.STRUCTURE_BUNDLE_DIR,
    });
    if (!structureResult.passed) {
      return {
        passed: false,
        reason: `🚫 **merge-gate blocked**\n\n${structureResult.reason}`,
        manifestPath,
        org,
        authorLogin,
        headSha,
        prNumber,
      };
    }
  }

  return { passed: true, reason: null, manifestPath, org, authorLogin, headSha, prNumber };
}

/** Merge the PR via the App installation token (D-08 / AUTH-04). */
export async function mergePr(gh, repo, prNumber, headSha, commitTitle) {
  const res = await gh(`/repos/${repo}/pulls/${prNumber}/merge`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      commit_title: commitTitle,
      merge_method: "squash",
      sha: headSha, // pin the head — 409 on drift is handled by the caller
    }),
  });
  return res;
}
