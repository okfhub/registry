#!/usr/bin/env node
// gate-merge.mjs — the MERGE half of the split merge-gate (Phase 3, AUTH-04 / D-08).
//
// Runs on: workflow_run (the merge-gate-check workflow completing). The
// workflow_run event fires in the DEFAULT-BRANCH context, so repo secrets AND
// variables ARE available here — unlike the fork pull_request context. That's
// why the App private key (secret OKFHUB_APP_PRIVATE_KEY) is referenced here,
// not in the check workflow.
//
// HOW IT FINDS THE PR: the workflow_run event payload carries `head_sha`. This
// script finds the PR whose head is that SHA via the GitHub API
// (GET /repos/{repo}/commits/{sha}/pulls), then RE-RUNS the four checks
// (evaluatePullRequest) against the live PR state — it does NOT trust the check
// workflow's exit code. Re-deriving truth is defense-in-depth: if the PR head
// changed between the check run and this merge run, we evaluate the CURRENT
// head, never a stale one.
//
// On all-green: merges via the App installation token + posts a confirmation
// comment. On any failure: posts the failure comment (D-12 — no silent
// failures) and exits 1. The merge is the only action that needs the App token;
// the checks use the same token for convenience (it can read everything).
//
// Run by .github/workflows/merge-gate-merge.yml. Env contract:
//   GITHUB_TOKEN            — App installation token (from create-github-app-token)
//   GITHUB_REPOSITORY       — "okfhub/registry" (set by Actions)
//   GITHUB_EVENT_PATH       — path to the workflow_run event JSON (set by Actions)

import { readFile } from "node:fs/promises";
import { makeGh, evaluatePullRequest, postComment, mergePr } from "./gate-lib.mjs";

const REPO = process.env.GITHUB_REPOSITORY || "okfhub/registry";
const TOKEN = process.env.GITHUB_TOKEN;

async function readEvent() {
  const p = process.env.GITHUB_EVENT_PATH;
  if (!p) {
    throw new Error("GITHUB_EVENT_PATH not set — gate-merge must run inside a GitHub Action.");
  }
  return JSON.parse(await readFile(p, "utf8"));
}

/** Find the open PR for a workflow_run event. Returns the pull_request object,
 *  or null if none.
 *
 *  WHY NOT commits/{sha}/pulls: that endpoint returns only PRs whose head
 *  commit lives in THIS repo. A fork PR's head commit lives in the fork
 *  (asagajda/registry), so the upstream call returns []. That would make the
 *  merge step silently find no PR and merge nothing — the exact silent-failure
 *  trap this gate exists to prevent.
 *
 *  Instead use the pulls API's `head` filter with the `<owner>:<branch>` form,
 *  which is how GitHub documents cross-repo/fork PR lookup. The owner + branch
 *  both come from the workflow_run event payload (head_repository.full_name +
 *  head_branch), so this needs no extra API calls to derive. head_sha is the
 *  SHA we expect to see; we double-check it matches to avoid acting on a PR
 *  whose branch moved between the check and merge runs.
 */
async function findPrForWorkflowRun(gh, repo, workflowRun) {
  const headSha = workflowRun.head_sha;
  const headBranch = workflowRun.head_branch;
  // head_repository.full_name = "asagajda/registry"; owner = "asagajda".
  const headRepoFullName = workflowRun.head_repository?.full_name;
  if (!headSha || !headBranch || !headRepoFullName) {
    throw new Error(
      "gate-merge: workflow_run event missing head_sha / head_branch / head_repository — cannot find the PR.",
    );
  }
  const owner = headRepoFullName.split("/")[0];
  // `head` filter format: "<owner>:<branch>". Branch names can contain slashes
  // (publish/org-name-x-1.0.0); the pulls API accepts the full branch after the
  // first colon.
  const res = await gh(`/repos/${repo}/pulls?state=open&head=${encodeURIComponent(`${owner}:${headBranch}`)}`);
  if (!res.ok) {
    throw new Error(`pulls lookup HTTP ${res.status}`);
  }
  const prs = await res.json();
  // Match by SHA against the expected head. If the branch moved (force-push
  // between runs), the SHA won't match → return null → re-run on synchronize.
  return prs.find((p) => p.head?.sha === headSha && p.base?.ref === "main") || null;
}

async function main() {
  const event = await readEvent();
  const workflowRun = event.workflow_run;
  if (!workflowRun) {
    console.log("gate-merge: not a workflow_run event — nothing to do.");
    return;
  }

  const { gh } = makeGh(TOKEN);

  const pr = await findPrForWorkflowRun(gh, REPO, workflowRun);
  if (!pr) {
    // No open PR for this head — e.g. the check ran on a PR that has since been
    // closed/merged, or the branch moved (force-push) between the check and
    // merge runs. Nothing to do; a synchronize event will re-run the chain.
    console.log(`gate-merge: no open PR targeting main matching this workflow_run — nothing to merge.`);
    return;
  }
  const prNumber = pr.number;
  console.log(`gate-merge: evaluating PR #${prNumber} (head ${pr.head?.sha?.slice(0, 8)}) — re-running all checks.`);

  // Re-derive truth from the live PR state (defense-in-depth — does not trust
  // the check workflow's exit code).
  const result = await evaluatePullRequest(gh, REPO, pr);

  if (!result.passed) {
    // D-12: post the failure comment (this workflow has the App token that CAN
    // comment, unlike the fork-PR check workflow).
    await postComment(gh, REPO, prNumber, result.reason);
    console.error(`gate-merge: PR #${prNumber} FAILED checks — comment posted, not merged.`);
    process.exit(1);
  }

  // INFRA PR (no manifest, authored by a push-permission collaborator): the
  // gate approved the author, but we do NOT auto-merge maintenance changes — a
  // human merges those. Post a comment so the PR is not silent, and exit 0 (the
  // required `check` status stays green; the ruleset's required check is then
  // satisfiable, but the human-controlled merge step is the actual landing).
  // This keeps the publish-only auto-merge contract intact.
  if (result.infra) {
    await postComment(
      gh,
      REPO,
      prNumber,
      `✅ **merge-gate: approved (infra PR)** — author \`${result.authorLogin}\` has push permission; no manifest to gate. A maintainer merges this. (Publish PRs auto-merge; infra PRs are human-merged by design.)`,
    );
    console.log(`gate-merge: PR #${prNumber} is an approved infra PR — comment posted, NOT auto-merged.`);
    return;
  }

  // ALL GREEN — publish PR, merge via the App installation token (D-08 / AUTH-04).
  const commitTitle = `${result.manifestPath} (auto-merge by okfhub merge-gate)`;
  const mergeRes = await mergePr(gh, REPO, prNumber, result.headSha, commitTitle);
  if (mergeRes.status === 409) {
    // Head SHA drifted between evaluate and merge (force-push). Re-running the
    // Action (synchronize → check → workflow_run) recomputes the new head.
    await postComment(
      gh,
      REPO,
      prNumber,
      "⚠️ merge-gate: head SHA changed between the check and the merge call (409). The gate did not merge a stale head — re-running on the new head.",
    );
    console.error("gate-merge: 409 on merge (head drift).");
    process.exit(1);
  }
  if (!mergeRes.ok) {
    const body = await mergeRes.json().catch(() => ({}));
    await postComment(
      gh,
      REPO,
      prNumber,
      `⚠️ merge-gate: merge endpoint returned HTTP ${mergeRes.status} — ${body.message || "unknown error"}. Checks passed but the merge failed; a maintainer should investigate.`,
    );
    console.error(`gate-merge: merge HTTP ${mergeRes.status}: ${JSON.stringify(body)}`);
    process.exit(1);
  }

  await postComment(
    gh,
    REPO,
    prNumber,
    `✅ **merge-gate: merged** \`${result.manifestPath}\` — all checks passed (schema, path-scope, ownership, rate-limit). The registry.json rebuild will run shortly via build-registry.yml.`,
  );
  console.log(`✅ gate-merge: merged PR #${prNumber} (${result.manifestPath}).`);
}

main().catch(async (e) => {
  console.error(`gate-merge failed: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
