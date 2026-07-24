// path-scope.mjs — path-scope check (Phase 3, D-07).
//
// Defense-in-depth: every file a publish PR touches must live under the PR's
// own namespace path `io.github.<org>/`. This stops a PR that sneaks in edits
// to registry.json, .github/workflows/, another org's directory, or more than
// one namespace. Applies regardless of who opened the PR (D-07) — a
// maintainer's broad token can't publish into another namespace via this flow.
//
// The changed-files list comes from GET /repos/okfhub/registry/pulls/{n}/files.

/**
 * Parse the <org> segment from an io.github.<org>/<name>.json path.
 * Returns null if the path isn't under io.github.* (the schema check catches
 * non-io.github manifests; this is a belt-and-braces helper).
 * @param {string} p
 * @returns {string | null}
 */
function namespaceOrgFromPath(p) {
  const m = String(p ?? "").match(/^io\.github\.([a-z0-9-]+)\//);
  return m ? m[1] : null;
}

/**
 * @param {object} args
 * @param {string[]} args.changedFiles  Paths the PR modifies (from the GitHub pulls/files API).
 * @param {string} args.org            The <org> the PR is publishing into (parsed from its target manifest path by the caller).
 * @returns {{passed: boolean, reason: string}}
 */
export function checkPathScope({ changedFiles, org }) {
  const files = Array.isArray(changedFiles) ? changedFiles : [];
  const o = String(org ?? "").trim();

  if (files.length === 0) {
    return { passed: false, reason: "path-scope: PR changed no files." };
  }

  const allowedPrefix = `io.github.${o}/`;
  const offenders = [];

  for (const f of files) {
    const fileOrg = namespaceOrgFromPath(f);
    if (fileOrg === null) {
      // File isn't under any io.github.<org>/ — registry.json, .github/, etc.
      offenders.push(`${f} (outside io.github.* namespace tree)`);
      continue;
    }
    if (!f.startsWith(allowedPrefix)) {
      // Under io.github.* but a DIFFERENT org — cross-namespace injection.
      offenders.push(`${f} (cross-namespace: targets io.github.${fileOrg}, PR org is '${o}')`);
    }
  }

  if (offenders.length > 0) {
    return {
      passed: false,
      reason: `path-scope: ${offenders.length} file(s) outside io.github.${o}/: ${offenders.join("; ")}.`,
    };
  }

  return {
    passed: true,
    reason: `path-scope: all ${files.length} file(s) under io.github.${o}/.`,
  };
}

// Exported for tests / reuse by merge-gate.mjs.
export { namespaceOrgFromPath };
