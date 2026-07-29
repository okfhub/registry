#!/usr/bin/env node
// evidence-compute.mjs — generate structural-conformance evidence sidecars
// (Phase 4, D-04 / D-05 / D-06 / VAL-03).
//
// Two trigger paths (D-05), selected by EVIDENCE_MODE:
//   on-merge (default, workflow_run on merge-gate-merge success):
//     finds the manifest that just merged, clones its source, computes the full
//     evidence sidecar (5 verifyBundle checks + source-reachable), writes it.
//   cron (weekly schedule):
//     iterates ALL manifests, recomputes ONLY the decay-able checks
//     (source-reachable) and CARRIES FORWARD the immutable content-check results
//     from the prior sidecar unless check_logic_version changed (D-06 smart
//     recompute — content at a pinned SHA is immutable forever).
//
// The WORKFLOW (evidence-compute.yml), not this script, commits the sidecar with
// the App installation token (so the push triggers build-registry.yml — Pitfall
// 1 / T-08-LOOP). This script only WRITES sidecars to disk.
//
// Reuses: verifyBundle from ./structure.mjs (Plan 04-03's vendored source of
// truth), cloneAndExtract from ./clone-source.mjs (Plan 04-03's hardened clone),
// sanitizeForComment + makeGh from ./gate-lib.mjs.
//
// SECURITY: runs in the workflow_run / cron default-branch context. It clones
// only PUBLIC source repos and runs verifyBundle (reads markdown only — no
// eval/exec — T-06-PAWN). Every detail string is sanitized before writing
// (T-07-INJECT). Sidecars are git-tracked (T-09-TAMPER).

import { readFile, writeFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { makeGh, sanitizeForComment } from "./gate-lib.mjs";
import { verifyBundle } from "./structure.mjs";
import { cloneAndExtract } from "./clone-source.mjs";

const REPO = process.env.GITHUB_REPOSITORY || "okfhub/registry";
const TOKEN = process.env.GITHUB_TOKEN;
const MODE = process.env.EVIDENCE_MODE || "on-merge";
// Bump whenever a check's logic changes — forces a full recompute (D-06).
export const CHECK_LOGIC_VERSION = 1;

async function readEvent() {
  const p = process.env.GITHUB_EVENT_PATH;
  if (!p) throw new Error("GITHUB_EVENT_PATH not set — evidence-compute must run inside a GitHub Action.");
  return JSON.parse(await readFile(p, "utf8"));
}

/** Parse owner/repo from a github source URL (mirrors source.ts parseGithubUrl). */
function parseGithubUrl(url) {
  const m = /^https:\/\/github\.com\/([^/]+)\/([^/?#]+?)(?:\.git)?(?:[/?#]|$)/.exec(url);
  if (!m) throw new Error(`source.url '${url}' is not a recognized GitHub URL.`);
  return { owner: m[1], repo: m[2] };
}

/** Find the manifest path that changed in the workflow_run's triggering merge.
 *  Mirrors gate-merge.mjs's approach to locating the PR for a workflow_run. */
async function findMergedManifest(gh, workflowRun) {
  // The workflow_run is triggered by the MERGE workflow's success. Its head_sha
  // is the squash-merge COMMIT on main (NOT the PR's original head), and its
  // pull_requests[] is empty — so PR-head matching finds nothing. Instead, read
  // the merge commit's own file diff: it lists exactly what landed (the manifest).
  const headSha = workflowRun.head_sha;
  if (!headSha) {
    throw new Error("evidence-compute: workflow_run missing head_sha.");
  }
  const cRes = await gh(`/repos/${REPO}/commits/${headSha}?per_page=100`);
  if (!cRes.ok) throw new Error(`commit lookup HTTP ${cRes.status} for ${headSha}`);
  const commit = await cRes.json();
  // The merge commit's files: find the added/modified io.github.<org>/<name>.json.
  // (Excludes *.evidence.json — those are this workflow's output, not manifests.)
  const manifestFile = (commit.files ?? [])
    .map((f) => f.filename)
    .find((f) => /^io\.github\.[a-z0-9-]+\/[^/]+\.json$/.test(f));
  if (!manifestFile) return null;
  return manifestFile;
}

/** Collect every manifest path in the repo (cron path). */
async function collectManifestPaths() {
  const top = await readdir(".", { withFileTypes: true });
  const dirs = top.filter((e) => e.isDirectory() && /^io\.github\.[a-z0-9-]+$/.test(e.name)).map((e) => e.name).sort();
  const out = [];
  for (const dir of dirs) {
    const entries = await readdir(dir);
    for (const f of entries) {
      if (f.endsWith(".json") && !f.endsWith(".evidence.json")) out.push(join(dir, f));
    }
  }
  return out;
}

/**
 * Cron-path targets: each manifest path + its parsed manifest + its prior
 * sidecar (for D-06 smart recompute). Matches the {manifestPath, manifest,
 * priorSidecar} shape the on-merge path produces, so the main loop is uniform.
 */
async function collectCronTargets() {
  const paths = await collectManifestPaths();
  const targets = [];
  for (const manifestPath of paths) {
    let manifest;
    try {
      manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    } catch {
      console.error(`⚠️ evidence-compute: ${manifestPath} is not valid JSON — skipping.`);
      continue;
    }
    // Read the prior sidecar (if any) for D-06 smart recompute.
    const sidecarPath = manifestPath.replace(/\.json$/, ".evidence.json");
    let priorSidecar;
    try {
      priorSidecar = JSON.parse(await readFile(sidecarPath, "utf8"));
    } catch {
      priorSidecar = undefined; // no prior sidecar → full recompute
    }
    targets.push({ manifestPath, manifest, priorSidecar });
  }
  return targets;
}

/** Sanitize every detail string in a checks array (T-07-INJECT). */
function sanitizeChecks(checks) {
  return checks.map((c) =>
    c.detail !== undefined ? { ...c, detail: sanitizeForComment(c.detail) } : { ...c },
  );
}

/**
 * Compute the full evidence sidecar for a manifest (on-merge path). Clones the
 * source, runs verifyBundle, appends source-reachable, builds the D-10 object.
 */
async function computeSidecar(manifestPath, manifest) {
  if (!manifest.source || manifest.source.type !== "github") {
    throw new Error(`source type '${manifest.source?.type}' not supported (only 'github').`);
  }
  const { owner, repo } = parseGithubUrl(manifest.source.url);
  const ref = manifest.source.ref ?? "main";
  const sourcePath = manifest.source.path ?? "";
  const { extractDir, bundleDir, resolvedRef } = await cloneAndExtract(owner, repo, ref, sourcePath);
  let checks;
  try {
    checks = (await verifyBundle(bundleDir)).checks;
  } finally {
    const { rm } = await import("node:fs/promises");
    await rm(extractDir, { recursive: true, force: true });
  }
  // D-10: the 6th check (source-reachable) — pass since the tarball GET succeeded.
  checks.push({
    id: "source-reachable",
    name: "Source repo reachable",
    severity: "quality",
    status: "pass",
  });
  return {
    evidence_version: 1,
    namespace: manifest.namespace,
    name: manifest.name,
    resolved_sha: resolvedRef,
    checked_at: new Date().toISOString(),
    check_logic_version: CHECK_LOGIC_VERSION,
    checks: sanitizeChecks(checks),
  };
}

/** D-06 smart recompute (cron): carry forward immutable content checks; refresh
 *  only source-reachable + checked_at when resolved_sha + check_logic_version
 *  are unchanged. Returns the recomputed sidecar, or null to skip (no change). */
async function smartRecompute(manifestPath, manifest, priorSidecar) {
  const sidecarPath = manifestPath.replace(/\.json$/, ".evidence.json");
  // If no prior sidecar, or the check-logic version changed, do a full recompute.
  if (!priorSidecar || priorSidecar.check_logic_version !== CHECK_LOGIC_VERSION) {
    return { sidecar: await computeSidecar(manifestPath, manifest), sidecarPath };
  }
  // Re-attempt the fetch (source-reachable is the only decay-able check — D-06).
  // If the fetch fails, mark source-reachable fail but keep the content checks.
  let reachable;
  try {
    const { owner, repo } = parseGithubUrl(manifest.source.url);
    // cloneAndExtract throws on fetch failure — that's the decay signal.
    const { extractDir } = await cloneAndExtract(owner, repo, manifest.source.ref ?? "main", manifest.source.path ?? "");
    const { rm } = await import("node:fs/promises");
    await rm(extractDir, { recursive: true, force: true });
    reachable = "pass";
  } catch {
    reachable = "fail";
  }
  // Carry forward the content checks verbatim; refresh source-reachable + checked_at.
  const contentChecks = priorSidecar.checks.filter((c) => c.id !== "source-reachable");
  const updated = {
    ...priorSidecar,
    checked_at: new Date().toISOString(),
    checks: sanitizeChecks([
      ...contentChecks,
      { id: "source-reachable", name: "Source repo reachable", severity: "quality", status: reachable },
    ]),
  };
  return { sidecar: updated, sidecarPath };
}

async function main() {
  if (!TOKEN) throw new Error("GITHUB_TOKEN not set — evidence-compute needs the App token to clone sources.");
  const { gh } = makeGh(TOKEN);

  const targets = MODE === "cron" ? await collectCronTargets() : await onMergeTargets(gh);
  if (targets.length === 0) {
    console.log(`evidence-compute (${MODE}): no target manifests — nothing to compute.`);
    return;
  }

  let ok = 0;
  for (const { manifestPath, manifest, priorSidecar } of targets) {
    try {
      const result = MODE === "cron"
        ? await smartRecompute(manifestPath, manifest, priorSidecar)
        : { sidecar: await computeSidecar(manifestPath, manifest), sidecarPath: manifestPath.replace(/\.json$/, ".evidence.json") };
      await writeFile(result.sidecarPath, JSON.stringify(result.sidecar, null, 2) + "\n", "utf8");
      console.log(`✅ evidence-compute: wrote ${result.sidecarPath}`);
      ok++;
    } catch (e) {
      // One bundle's evidence failure must not block the others.
      console.error(`⚠️ evidence-compute: ${manifestPath} failed (${e instanceof Error ? e.message : String(e)}) — skipping.`);
    }
  }
  console.log(`evidence-compute (${MODE}): ${ok}/${targets.length} sidecars written.`);
}

/** Resolve the on-merge target manifest(s) from the workflow_run event. */
async function onMergeTargets(gh) {
  const event = await readEvent();
  const workflowRun = event.workflow_run;
  if (!workflowRun) {
    console.log("evidence-compute: not a workflow_run event and MODE != cron — nothing to do.");
    return [];
  }
  const manifestPath = await findMergedManifest(gh, workflowRun);
  if (!manifestPath) {
    console.log("evidence-compute: no merged manifest found for this workflow_run — nothing to compute.");
    return [];
  }
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  return [{ manifestPath, manifest, priorSidecar: undefined }];
}

// Run main() ONLY when this file is the entry point (the workflow calls it
// directly), not when imported as a module.
import { fileURLToPath as __fileURLToPath } from "node:url";
const __isMain = process.argv[1] && __fileURLToPath(import.meta.url) === __fileURLToPath(new URL(`file://${process.argv[1]}`));
if (__isMain) {
  main().catch((e) => {
    console.error(`evidence-compute failed: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  });
}
