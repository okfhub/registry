#!/usr/bin/env node
// merge-gate.mjs — the self-merging publish-PR gate (Phase 3, AUTH-04 / D-08).
//
// This orchestrator is BOTH checker AND merger (D-08). It runs on pull_request
// (opened/synchronize/reopened) targeting main, evaluates four checks in order
// (schema → path-scope → ownership → rate-limit, fail-fast), and:
//   - on ALL-green: calls PUT /repos/okfhub/registry/pulls/{n}/merge (squash)
//   - on ANY failure: posts a PR comment naming the failed check, the seen
//     value, and the expected value (D-12 — no silent failures), and exits 1.
//
// IDENTITY INVARIANT (D-05): the author login comes from
// `pull_request.user.login` in the event payload ONLY — never from the PR body.
// The ownership check's signature takes authorLogin as a parameter; there is
// no body parameter anywhere in this file.
//
// TOKEN (D-11): the Action mints an App INSTALLATION token via
// actions/create-github-app-token and passes it here as GITHUB_TOKEN. The App's
// private key NEVER enters the CLI or this script — it lives as the repo
// secret OKFHUB_APP_PRIVATE_KEY, used only by the token-mint step. Using the
// App installation token (NOT the default GITHUB_TOKEN) means the merge push
// triggers the downstream build-registry.yml (default GITHUB_TOKEN cannot).
//
// Run by .github/workflows/merge-gate.yml. Env contract:
//   GITHUB_TOKEN            — App installation token (from create-github-app-token)
//   GITHUB_REPOSITORY       — "okfhub/registry" (set by Actions)
//   GITHUB_EVENT_PATH       — path to the pull_request event JSON (set by Actions)
//   GITHUB_API_URL          — https://api.github.com (set by Actions, defaulted)
//   REGISTRY_POLICY_PATH    — path to registry-policy.json (default ./registry-policy.json)

import { readFile } from "node:fs/promises";

import { checkSchema } from "./schema.mjs";
import { checkPathScope, namespaceOrgFromPath } from "./path-scope.mjs";
import { checkOwnership } from "./ownership.mjs";
import { checkRateLimit } from "./rate-limit.mjs";

const API = process.env.GITHUB_API_URL || "https://api.github.com";
const REPO = process.env.GITHUB_REPOSITORY || "okfhub/registry";
const TOKEN = process.env.GITHUB_TOKEN;
const POLICY_PATH = process.env.REGISTRY_POLICY_PATH || "registry-policy.json";

function authHeaders() {
  const h = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (TOKEN) {
    h.Authorization = `token ${TOKEN}`;
  }
  return h;
}

async function gh(path, init = {}) {
  const url = path.startsWith("http") ? path : `${API}${path}`;
  const res = await fetch(url, { ...init, headers: { ...authHeaders(), ...(init.headers || {}) } });
  return res;
}

async function readEvent() {
  const p = process.env.GITHUB_EVENT_PATH;
  if (!p) {
    throw new Error("GITHUB_EVENT_PATH not set — merge-gate must run inside a GitHub Action.");
  }
  return JSON.parse(await readFile(p, "utf8"));
}

/** Fetch the full list of changed files for a PR (paginated — uses per_page=100). */
async function fetchChangedFiles(prNumber) {
  const res = await gh(`/repos/${REPO}/pulls/${prNumber}/files?per_page=100`);
  if (!res.ok) {
    throw new Error(`pulls/files HTTP ${res.status}`);
  }
  const files = await res.json();
  return files.map((f) => f.filename);
}

/** Fetch the manifest JSON a PR publishes (from the head branch), if any. */
async function fetchManifestAt(prNumber, filePath) {
  const prRes = await gh(`/repos/${REPO}/pulls/${prNumber}`);
  if (!prRes.ok) throw new Error(`pulls HTTP ${prRes.status}`);
  const pr = await prRes.json();
  const headSha = pr.head?.sha;
  const cRes = await gh(`/repos/${REPO}/contents/${filePath}?ref=${headSha}`);
  if (!cRes.ok) return null; // file not present at head (e.g. a deletion PR)
  const c = await cRes.json();
  if (c.encoding !== "base64" || typeof c.content !== "string") return null;
  const text = Buffer.from(c.content, "base64").toString("utf8");
  return JSON.parse(text);
}

/** Does the target manifest file already exist on main (version-update vs new)? */
async function targetFileExistsOnMain(filePath) {
  const res = await gh(`/repos/${REPO}/contents/${filePath}?ref=main`);
  return res.ok;
}

/** Count the author's PRs to this repo today (per-identity rate-limit input). */
async function countAuthorPrsToday(authorLogin) {
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD UTC
  const q = `repo:${REPO}+type:pr+author:${authorLogin}+created:>=${today}`;
  const res = await gh(`/search/issues?q=${encodeURIComponent(q)}&per_page=1`);
  if (!res.ok) return 0; // degrade-open on search failure (logged elsewhere)
  const j = await res.json();
  return j.total_count ?? 0;
}

/** Count ALL PRs to this repo in the last hour (circuit-breaker input). */
async function countRegistryPrsLastHour() {
  const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const q = `repo:${REPO}+type:pr+created:>=${since}`;
  const res = await gh(`/search/issues?q=${encodeURIComponent(q)}&per_page=1`);
  if (!res.ok) return 0;
  const j = await res.json();
  return j.total_count ?? 0;
}

/** Post a comment on the PR naming the failed check (D-12 — no silent failures). */
async function postComment(prNumber, body) {
  await gh(`/repos/${REPO}/issues/${prNumber}/comments`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ body }),
  });
}

/** Merge the PR via the App installation token (D-08 / AUTH-04). */
async function mergePr(prNumber, headSha, commitTitle) {
  const res = await gh(`/repos/${REPO}/pulls/${prNumber}/merge`, {
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

async function main() {
  const event = await readEvent();
  const pr = event.pull_request;
  if (!pr) {
    console.log("merge-gate: not a pull_request event — nothing to do.");
    return;
  }
  const prNumber = pr.number;
  // D-05: identity from pull_request.user.login ONLY. Never pr.body.
  const authorLogin = pr.user?.login;
  const headSha = pr.head?.sha;
  if (!authorLogin || !headSha) {
    await postComment(
      prNumber,
      "⚠️ merge-gate: could not determine PR author login or head SHA from the event payload — refusing to merge (fail-closed).",
    );
    process.exit(1);
  }

  const changedFiles = await fetchChangedFiles(prNumber);
  // The target manifest = the io.github.<org>/<name>.json the PR publishes.
  const manifestPath = changedFiles.find((f) => /^io\.github\.[a-z0-9-]+\//.test(f));
  if (!manifestPath) {
    await postComment(
      prNumber,
      `⚠️ merge-gate: no \`io.github.<org>/<name>.json\` manifest found among the changed files (${changedFiles.join(", ")}). Publish PRs must add exactly one manifest under \`io.github.*\`.`,
    );
    process.exit(1);
  }
  const org = namespaceOrgFromPath(manifestPath);

  // 1) SCHEMA — fetch the manifest at head + validate (AUTH-03 enforced here).
  const manifestJson = await fetchManifestAt(prNumber, manifestPath);
  if (manifestJson === null) {
    await postComment(
      prNumber,
      `⚠️ merge-gate: could not read manifest \`${manifestPath}\` at the PR head — refusing to merge.`,
    );
    process.exit(1);
  }
  const schemaResult = checkSchema(manifestJson);
  if (!schemaResult.passed) {
    await postComment(prNumber, `🚫 **merge-gate blocked**\n\n${schemaResult.reason}`);
    console.error(schemaResult.reason);
    process.exit(1);
  }

  // 2) PATH-SCOPE (D-07).
  const pathResult = checkPathScope({ changedFiles, org });
  if (!pathResult.passed) {
    await postComment(prNumber, `🚫 **merge-gate blocked**\n\n${pathResult.reason}`);
    console.error(pathResult.reason);
    process.exit(1);
  }

  // 3) OWNERSHIP (AUTH-02 / D-05 / D-06). isOrgMember wired to the members API.
  const ownershipResult = await checkOwnership({
    org,
    authorLogin,
    isOrgMember: async (o, u) => {
      // 204 = member; 404/302/others = not a member. Fail-closed on non-2xx.
      const r = await gh(`/orgs/${o}/public_members/${u}`);
      return r.status === 204;
    },
  });
  if (!ownershipResult.passed) {
    await postComment(prNumber, `🚫 **merge-gate blocked**\n\n${ownershipResult.reason}`);
    console.error(ownershipResult.reason);
    process.exit(1);
  }

  // 4) RATE-LIMIT (D-10). Read thresholds from registry-policy.json.
  let policy = {};
  try {
    policy = JSON.parse(await readFile(POLICY_PATH, "utf8"));
  } catch (e) {
    console.error(`merge-gate: WARNING — could not read ${POLICY_PATH} (${e.message}); applying no limits.`);
  }
  const exists = await targetFileExistsOnMain(manifestPath);
  const todayByAuthor = await countAuthorPrsToday(authorLogin);
  const registryWideLastHour = await countRegistryPrsLastHour();
  const rateResult = checkRateLimit({
    authorLogin,
    targetFileExistsOnMain: exists,
    counts: { todayByAuthor, registryWideLastHour },
    policy,
  });
  if (!rateResult.passed) {
    // D-10: HOLD, never close. The comment names the limit + count + reset.
    await postComment(prNumber, `⏸️ **merge-gate held (rate-limit, not closed)**\n\n${rateResult.reason}`);
    console.error(rateResult.reason);
    process.exit(1);
  }

  // ALL GREEN — merge via the App installation token (D-08 / AUTH-04).
  const commitTitle = `${manifestPath} (auto-merge by okfhub merge-gate)`;
  const mergeRes = await mergePr(prNumber, headSha, commitTitle);
  if (mergeRes.status === 409) {
    // Edge-probe adjacency: head SHA drifted between check-run and merge
    // (force-push). Re-running the Action (synchronize trigger) recomputes
    // against the new head rather than merging a stale head.
    await postComment(
      prNumber,
      "⚠️ merge-gate: head SHA changed between the check run and the merge call (409). The gate did not merge a stale head — re-running on the new head.",
    );
    process.exit(1);
  }
  if (!mergeRes.ok) {
    const body = await mergeRes.json().catch(() => ({}));
    await postComment(
      prNumber,
      `⚠️ merge-gate: merge endpoint returned HTTP ${mergeRes.status} — ${body.message || "unknown error"}. Checks passed but the merge failed; a maintainer should investigate.`,
    );
    console.error(`merge HTTP ${mergeRes.status}: ${JSON.stringify(body)}`);
    process.exit(1);
  }

  console.log(`✅ merged PR #${prNumber} (${manifestPath}) — all checks passed.`);
}

main().catch(async (e) => {
  console.error(`merge-gate failed: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
