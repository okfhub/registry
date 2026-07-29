#!/usr/bin/env node
// gate-check.mjs — the CHECK half of the split merge-gate (Phase 3, AUTH-04).
//
// Runs on: pull_request (opened/synchronize/reopened) targeting main.
// This is the fork-PR context, where repo secrets AND variables are withheld.
// So this step uses ONLY the default GITHUB_TOKEN (always available) to fetch
// the PR state and run the four checks. It CANNOT post a comment (GITHUB_TOKEN
// lacks pull-requests:write on a fork PR) and CANNOT merge (needs the App token).
//
// Its job is to PRODUCE A PASS/FAIL SIGNAL: it exits 0 on all-green (which
// makes the check-run green), exit 1 on any failure (red check-run). The
// downstream gate-merge.mjs (on: workflow_run) watches this green signal to
// know the PR is safe to merge, then mints the App token and merges.
//
// If the check fails, gate-merge.mjs skips the merge and posts the failure
// comment (it has the App token that CAN comment). This keeps the "no silent
// failures" D-12 invariant intact even though the comment is posted by the
// second workflow, not this one.
//
// Run by .github/workflows/merge-gate-check.yml. Env contract:
//   GITHUB_TOKEN            — default Actions token (fork-PR safe; read-only use)
//   GITHUB_REPOSITORY       — "okfhub/registry" (set by Actions)
//   GITHUB_EVENT_PATH       — path to the pull_request event JSON (set by Actions)

import { readFile } from "node:fs/promises";
import { makeGh, evaluatePullRequest } from "./gate-lib.mjs";

const REPO = process.env.GITHUB_REPOSITORY || "okfhub/registry";
const TOKEN = process.env.GITHUB_TOKEN;

async function readEvent() {
  const p = process.env.GITHUB_EVENT_PATH;
  if (!p) {
    throw new Error("GITHUB_EVENT_PATH not set — gate-check must run inside a GitHub Action.");
  }
  return JSON.parse(await readFile(p, "utf8"));
}

async function main() {
  const event = await readEvent();
  const pr = event.pull_request;
  if (!pr) {
    console.log("gate-check: not a pull_request event — nothing to do.");
    return;
  }

  const { gh } = makeGh(TOKEN);
  const result = await evaluatePullRequest(gh, REPO, pr);

  if (result.passed) {
    console.log(
      `✅ gate-check: PR #${result.prNumber} (${result.manifestPath}) — all checks passed. ` +
        `gate-merge will pick this up via workflow_run and merge.`,
    );
    return; // exit 0 → green check-run
  }

  // The check FAILED. We cannot comment (fork-PR GITHUB_TOKEN can't write PRs).
  // Print the reason to the run log AND exit 1 → red check-run. The downstream
  // gate-merge.mjs reads this run's conclusion + the failure marker file, posts
  // the comment with its App token, and skips the merge.
  console.error(result.reason);
  console.error("gate-check: FAILED — exit 1. gate-merge will post this failure to the PR.");
  process.exit(1);
}

main().catch(async (e) => {
  console.error(`gate-check failed: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
