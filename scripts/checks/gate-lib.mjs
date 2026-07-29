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
import { checkPathScope, namespaceOrgFromPath } from "./path-scope.mjs";
import { checkOwnership } from "./ownership.mjs";
import { checkRateLimit } from "./rate-limit.mjs";
import { checkStructure } from "./structure.mjs";

const API = process.env.GITHUB_API_URL || "https://api.github.com";
const POLICY_PATH = process.env.REGISTRY_POLICY_PATH || "registry-policy.json";

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
 * Evaluate a publish PR against all four checks. PURE-ish: fetches PR state via
 * the given gh() fetcher, runs the checks, and returns a structured result.
 * Never calls process.exit, never posts comments, never merges — the caller
 * decides what to do with the result.
 *
 * @param {object} gh - fetcher from makeGh(token)
 * @param {string} repo - "okfhub/registry"
 * @param {object} pr - the pull_request object from the event payload
 * @returns {Promise<{passed: boolean, reason: string|null, manifestPath: string|null, org: string|null, authorLogin: string, headSha: string, prNumber: number}>}
 */
export async function evaluatePullRequest(gh, repo, pr) {
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
  // The target manifest = the io.github.<org>/<name>.json the PR publishes.
  const manifestPath = changedFiles.find((f) => /^io\.github\.[a-z0-9-]+\//.test(f));
  if (!manifestPath) {
    return {
      passed: false,
      reason: `⚠️ merge-gate: no \`io.github.<org>/<name>.json\` manifest found among the changed files (${changedFiles.map(sanitizeForComment).join(", ")}). Publish PRs must add exactly one manifest under \`io.github.*\`.`,
      manifestPath: null,
      org: null,
      authorLogin,
      headSha,
      prNumber,
    };
  }
  const org = namespaceOrgFromPath(manifestPath);

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
  if (typeof declaredNamespace !== "string" || declaredNamespace.toLowerCase() !== `io.github.${org}`) {
    return {
      passed: false,
      reason: `🚫 **merge-gate blocked**\n\nnamespace: manifest declares \`${sanitizeForComment(declaredNamespace)}\` but lives at path \`io.github.${org}/\` — the declared namespace must match the file's path. The CLI derives the path from the namespace by construction; a mismatch indicates a hand-crafted PR attempting namespace impersonation in the index.`,
      manifestPath,
      org,
      authorLogin,
      headSha,
      prNumber,
    };
  }

  // 2) PATH-SCOPE (D-07).
  const pathResult = checkPathScope({ changedFiles, org });
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

  // 3) OWNERSHIP (AUTH-02 / D-05 / D-06). isOrgMember wired to the members API.
  const ownershipResult = await checkOwnership({
    org,
    authorLogin,
    isOrgMember: async (o, u) => {
      // 204 = member; 404/302/others = not a member. Fail-closed on non-2xx.
      // Uses the public_members endpoint (no extra scope needed).
      const r = await gh(`/orgs/${o}/public_members/${u}`);
      return r.status === 204;
    },
  });
  if (!ownershipResult.passed) {
    // Audit H2: when ownership fails on the ORG-membership path (org ≠ author),
    // the public_members endpoint can't distinguish a private member from a
    // non-member. Append the self-serviceable fix so a legitimate but
    // private-member publisher isn't left guessing. The check function itself
    // stays generic; only the posted comment carries this product hint.
    const orgMembershipHint =
      org.toLowerCase() !== authorLogin.toLowerCase() && /member of org/.test(ownershipResult.reason)
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
