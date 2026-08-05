// path-scope.mjs — path-scope check (Phase 3, D-07; Phase 8 namespace-family dispatch).
//
// Defense-in-depth: every file a publish PR touches must live under the PR's
// own namespace path `io.<family>.<segment>/`. This stops a PR that sneaks in
// edits to registry.json, .github/workflows/, another namespace's directory, or
// more than one namespace. Applies regardless of who opened the PR (D-07) — a
// maintainer's broad token can't publish into another namespace via this flow.
//
// Phase 8 generalizes the io.github.<org>/ prefix to a per-family prefix:
//   - io.github.<org>/   (org-membership ownership — unchanged)
//   - io.http.<domain>/  (DNS-ownership — the segment is a domain, may contain
//                         dots + hyphens, e.g. io.http.example.com/)
// The changed-files list comes from GET /repos/okfhub/registry/pulls/{n}/files.

/**
 * Parse the <org> segment from an io.github.<org>/<name>.json path.
 * Returns null if the path isn't under io.github.* (the schema check catches
 * non-io.github manifests; this is a belt-and-braces helper).
 *
 * NOTE: for io.http.* paths use {@link namespaceFamilyFromPath} (the segment is
 * a domain and may contain dots). This helper stays github-only for backward
 * compatibility with existing callers/tests.
 * @param {string} p
 * @returns {string | null}
 */
function namespaceOrgFromPath(p) {
  const m = String(p ?? "").match(/^io\.github\.([a-z0-9-]+)\//);
  return m ? m[1] : null;
}

/**
 * Detect the namespace family + segment from a manifest path (Phase 8).
 *
 * Returns `{ family, segment }` where family is `"github"` or `"http"` and
 * segment is the org (for github) or the domain (for http — may contain dots +
 * hyphens, e.g. `example.com`). Returns `{ family: null, segment: null }` when
 * the path isn't under any io.<family>.<segment>/ tree (registry.json,
 * .github/, etc.).
 *
 * The family drives the gate's ownership dispatch: github → org-membership;
 * http → DNS-ownership. The segment drives the path-scope prefix.
 * @param {string} p
 * @returns {{family: "github"|"http"|null, segment: string|null}}
 */
export function namespaceFamilyFromPath(p) {
  const s = String(p ?? "");
  const gh = s.match(/^io\.github\.([a-z0-9-]+)\//);
  if (gh) return { family: "github", segment: gh[1] };
  const http = s.match(/^io\.http\.([a-z0-9.-]+)\//);
  if (http) return { family: "http", segment: http[1] };
  return { family: null, segment: null };
}

/**
 * @param {object} args
 * @param {string[]} args.changedFiles  Paths the PR modifies (from the GitHub pulls/files API).
 * @param {string} args.org            The <org> the PR is publishing into (parsed from its target manifest path by the caller). Used as the github segment when `family` is unset/`"github"` (backward compat).
 * @param {("github"|"http")} [args.family]  The namespace family (Phase 8). Defaults to `"github"` for backward compatibility — io.github.<org>/ stays the canonical path.
 * @param {string} [args.segment]      The family segment (org for github, domain for http). Falls back to `org` for backward compatibility.
 * @returns {{passed: boolean, reason: string}}
 */
export function checkPathScope({ changedFiles, org, family, segment }) {
  const files = Array.isArray(changedFiles) ? changedFiles : [];
  const fam = family ?? "github";
  // segment wins for the http family; org is the backward-compat github segment.
  const seg = fam === "http" ? String(segment ?? "").trim() : String(segment ?? org ?? "").trim();

  if (files.length === 0) {
    return { passed: false, reason: "path-scope: PR changed no files." };
  }

  const allowedPrefix = `io.${fam}.${seg}/`;
  const offenders = [];

  for (const f of files) {
    const fileFamily = namespaceFamilyFromPath(f);
    if (fileFamily.family === null) {
      // File isn't under any io.<family>.<segment>/ — registry.json, .github/, etc.
      offenders.push(`${f} (outside io.* namespace tree)`);
      continue;
    }
    if (!f.startsWith(allowedPrefix)) {
      // Under io.* but a DIFFERENT family/segment — cross-namespace injection.
      offenders.push(`${f} (cross-namespace: targets io.${fileFamily.family}.${fileFamily.segment}, PR is io.${fam}.${seg})`);
    }
  }

  if (offenders.length > 0) {
    return {
      passed: false,
      reason: `path-scope: ${offenders.length} file(s) outside io.${fam}.${seg}/: ${offenders.join("; ")}.`,
    };
  }

  return {
    passed: true,
    reason: `path-scope: all ${files.length} file(s) under io.${fam}.${seg}/.`,
  };
}

// Exported for tests / reuse by merge-gate.mjs.
export { namespaceOrgFromPath };
