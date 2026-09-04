// structure.mjs — structural identity check for the merge-gate (Phase 4, D-02 / D-08).
//
// VENDORED from okfhub-cli/src/lib/verify.ts — keep in sync (CLI is source of
// truth). The verify logic is the 4th shared contract (after ManifestSchema's 3
// copies: schema.mjs here, manifest.ts in the CLI, types in the website). One
// source of truth, three callers (CLI verify, publish pre-flight, this gate).
//
// The vendored parseBundle + walkMd come from okfhub-cli/src/lib/okf-parser.ts
// (gray-matter frontmatter parsing + the collect-all-errors philosophy).
//
// PITFALL 3 mitigation #3: this module is SMALL + PURE — it takes a bundleDir
// and reads files only. No network. That is what makes it safe to run in the
// fork-PR check half (T-06-PAWN): it never executes PR-authored code, only
// reads markdown (gray-matter frontmatter + a link regex).
//
// SECURITY (T-04-PATH): link-target resolution rejects any target escaping the
// bundle dir via relative(bundleDir, resolved).startsWith("..") — mirrors
// isSafePath in okfhub-cli/src/lib/source.ts. detail strings pass through
// sanitizeForComment (imported from gate-lib.mjs) before entering {reason}
// (T-07-INJECT — detail can carry user-controlled bundle file paths).

import { readFile, readdir, stat } from "node:fs/promises";
import { dirname, join, normalize, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import matter from "gray-matter";
import { z } from "zod";
import { sanitizeForComment } from "./gate-lib.mjs";

// Resolve gray-matter/zod from THIS package's node_modules (scripts/checks), not
// the gate runner's ambient resolution. import.meta.url anchors it regardless of cwd.
const __dirname = dirname(fileURLToPath(import.meta.url));

// Minimal frontmatter check: only `type` is required (SPEC §9). Mirrors
// okfhub-cli/src/lib/okf-parser.ts ConceptFrontmatter.
const ConceptFrontmatter = z
  .object({ type: z.string().min(1) })
  .passthrough();

const RESERVED = new Set(["index.md", "log.md"]);

/**
 * Walk bundleDir, gray-matter each .md, validate per SPEC §9. Reserved files
 * (index.md, log.md) are SKIPPED. Collects ALL errors (ERR-03).
 * VENDORED from okfhub-cli/src/lib/okf-parser.ts parseBundle + walkMd.
 *
 * PHASE 5 EXTENSION (D-04/D-05): each concept now also carries its parsed
 * `frontmatter` object and the full `body` markdown text (frontmatter + body —
 * the verbatim `.md` that becomes an MCP resource). The CLI source of truth
 * (okf-parser.ts) returns `{relPath, frontmatter, type}`; this vendored copy
 * adds `body` for the materialization pipeline only (the gateway needs the raw
 * text). Keep the body read here so parseBundle is the single walk of the tree
 * (no second readdir/readFile pass in computeEvidence).
 *
 * @param {string} bundleDir
 * @returns {Promise<{concepts: Array<{relPath: string, type: string, frontmatter: object, body: string}>, errors: Array<{file: string, problem: string}>, reservedSkipped: string[]}>}
 */
export async function parseBundle(bundleDir) {
  const concepts = [];
  const errors = [];
  const reservedSkipped = [];

  const files = await walkMd(bundleDir);
  for (const abs of files) {
    const relPath = relative(bundleDir, abs).split(sep).join("/");
    const base = relPath.split("/").pop() ?? relPath;

    if (RESERVED.has(base)) {
      reservedSkipped.push(relPath);
      continue;
    }

    let parsed;
    try {
      parsed = matter.read(abs);
    } catch (e) {
      errors.push({
        file: relPath,
        problem: `frontmatter is not valid YAML: ${e instanceof Error ? e.message : String(e)}`,
      });
      continue;
    }

    // The full markdown text — read ONCE, reused for both the frontmatter-block
    // check AND the materialized `body` artifact (Phase 5). This is the MCP
    // resource text (raw .md, D-05). Never eval'd (T-06-PAWN — read as text only).
    const body = await readFile(abs, "utf8");
    if (!body.trimStart().startsWith("---")) {
      errors.push({ file: relPath, problem: "missing YAML frontmatter block" });
      continue;
    }

    const result = ConceptFrontmatter.safeParse(parsed.data);
    if (!result.success) {
      errors.push({ file: relPath, problem: "missing or empty required 'type' field" });
      continue;
    }

    concepts.push({
      relPath,
      type: result.data.type,
      frontmatter: result.data,
      body,
    });
  }

  return { concepts, errors, reservedSkipped };
}

/**
 * Recursively collect all .md files under dir (absolute paths).
 *
 * PHASE 5 EXTENSION (T-04-SYM): symlink/hardlink entries are SKIPPED, not
 * followed. OKF bundles are pure markdown; a symlink concept could point
 * outside the bundle dir (the T-04-SYM threat for materialized artifacts —
 * fs.readFile on a materialized symlink would escape public/). The clone-time
 * guard in cloneAndExtract (isSafeEntry) already rejects symlink tar entries;
 * this walk-time guard is the defense-in-depth backstop for any path that
 * bypasses tar extraction. Mirrors the Phase-4 isSafeLinkTarget philosophy.
 */
async function walkMd(dir) {
  const out = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    const full = join(dir, e.name);
    // T-04-SYM: never descend into or collect a symlink/hardlink. dirent-type
    // checks are race-free vs. lstat reads on macOS/Linux.
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) {
      out.push(...(await walkMd(full)));
    } else if (e.isFile() && e.name.endsWith(".md")) {
      out.push(full);
    }
  }
  return out;
}

/**
 * verifyBundle — the single source of truth (D-03). PURE: reads bundleDir only,
 * no network. Returns the 5 checks computable from a local bundle directory
 * (4 identity + links-resolve quality). The 6th check (source-reachable) is
 * caller-recorded (a fetch-time fact).
 *
 * VENDORED from okfhub-cli/src/lib/verify.ts verifyBundle.
 *
 * @param {string} bundleDir
 * @returns {Promise<{checks: Array<{id: string, name: string, severity: "identity"|"quality", status: "pass"|"warn"|"fail"|"skipped", detail?: string}>}>}
 */
export async function verifyBundle(bundleDir) {
  let parsed;
  try {
    parsed = await parseBundle(bundleDir);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      checks: [
        check("bundle-root", "Bundle root exists", "identity", "fail", `could not read bundle directory: ${msg}`),
        check("frontmatter", "Frontmatter parses", "identity", "fail", "bundle directory not readable"),
        check("type-present", "type field present", "identity", "fail", "bundle directory not readable"),
        check("min-concepts", "≥1 concept", "identity", "fail", "no concepts (bundle directory not readable)"),
        check("links-resolve", "Internal links resolve", "quality", "skipped"),
      ],
    };
  }

  const { concepts, errors } = parsed;

  const bundleRoot = check("bundle-root", "Bundle root exists", "identity", "pass");

  const fmFails = errors.filter((e) => /frontmatter|yaml/i.test(e.problem));
  const frontmatter = fmFails.length > 0
    ? check("frontmatter", "Frontmatter parses", "identity", "fail", fmFails.map((e) => e.file).join(", "))
    : check("frontmatter", "Frontmatter parses", "identity", "pass");

  const typeFails = errors.filter((e) => /type/i.test(e.problem));
  const typePresent = typeFails.length > 0
    ? check("type-present", "type field present", "identity", "fail", typeFails.map((e) => e.file).join(", "))
    : check("type-present", "type field present", "identity", "pass");

  const minConcepts = concepts.length < 1
    ? check("min-concepts", "≥1 concept", "identity", "fail", "no concept documents found")
    : check("min-concepts", "≥1 concept", "identity", "pass");

  const dangling = await findDanglingLinks(bundleDir, concepts);
  const linksResolve = dangling.length === 0
    ? check("links-resolve", "Internal links resolve", "quality", "pass")
    : check("links-resolve", "Internal links resolve", "quality", "warn", formatDangling(dangling));

  return { checks: [bundleRoot, frontmatter, typePresent, minConcepts, linksResolve] };
}

function check(id, name, severity, status, detail) {
  return detail !== undefined ? { id, name, severity, status, detail } : { id, name, severity, status };
}

async function findDanglingLinks(bundleDir, concepts) {
  const dangling = [];
  for (const concept of concepts) {
    let body;
    try {
      body = await readFile(join(bundleDir, concept.relPath), "utf8");
    } catch {
      continue;
    }
    const stripped = stripCode(body);
    const targets = extractLinkTargets(stripped);
    const conceptDir = dirname(concept.relPath);
    for (const target of targets) {
      if (!isInternal(target)) continue;
      const pathOnly = targetPath(target);
      if (pathOnly === "") continue;
      const resolved = normalize(join(bundleDir, conceptDir, pathOnly));
      if (relative(bundleDir, resolved).startsWith("..")) {
        dangling.push({ file: concept.relPath, target });
        continue;
      }
      if (!(await exists(resolved))) {
        dangling.push({ file: concept.relPath, target });
      }
    }
  }
  return dangling;
}

/**
 * PHASE 10 (D-03): graph-edge extraction — reuses the SAME resolution logic as
 * findDanglingLinks (extractLinkTargets + isInternal + targetPath + the
 * relative(bundleDir, resolved).startsWith("..") escape rejection) but instead
 * of only counting dangling targets emits BOTH resolved and broken edges for
 * the concept graph build (build-registry.mjs buildGraph → public/graphs.json).
 *
 * findDanglingLinks itself is UNCHANGED — it still feeds the links-resolve
 * warn check. This sibling walks the same targets a second time (cheap: same
 * files, same regexes) so the two concerns stay decoupled.
 *
 * SECURITY (T-10-01): a target escaping the bundle dir (../../etc/passwd) is
 * rejected by the SAME guard verbatim and emitted as a BROKEN edge with the
 * raw pathOnly as endpoint — never resolved outside the bundle. The endpoint
 * is bundle-author-controlled content rendered on the website; ConceptGraph
 * renders it escaped (React text), never as a navigable path.
 *
 * @param {string} bundleDir
 * @param {Array<{relPath: string}>} concepts - parseBundle concepts (body may be absent; re-read from disk like findDanglingLinks)
 * @returns {Promise<Array<{from: string, to: string, broken?: boolean}>>}
 *   from/to are concept ids = relPath minus the .md suffix.
 */
export async function extractGraphEdges(bundleDir, concepts) {
  const edges = [];
  const idOf = (relPath) => relPath.replace(/\.md$/, "");
  for (const concept of concepts) {
    let body;
    try {
      body = await readFile(join(bundleDir, concept.relPath), "utf8");
    } catch {
      continue;
    }
    const stripped = stripCode(body);
    const targets = extractLinkTargets(stripped);
    const conceptDir = dirname(concept.relPath);
    const from = idOf(concept.relPath);
    for (const target of targets) {
      if (!isInternal(target)) continue;
      const pathOnly = targetPath(target);
      if (pathOnly === "") continue;
      const resolved = normalize(join(bundleDir, conceptDir, pathOnly));
      if (relative(bundleDir, resolved).startsWith("..")) {
        // Escape rejection (T-10-01 — same guard as findDanglingLinks): surface
        // as a broken edge with the raw target, never resolve outside the bundle.
        edges.push({ from, to: pathOnly, broken: true });
        continue;
      }
      const found = await resolveTarget(resolved);
      if (found) {
        // Resolved target → a real edge. The endpoint is the resolved file's
        // bundle-relative path minus .md so it matches GraphNode.id even when
        // the link and the target live in different directories.
        const rel = relative(bundleDir, found).split(sep).join("/");
        edges.push({ from, to: idOf(rel) });
      } else {
        // Does not exist → broken edge (ConceptGraph.tsx renders e[2]===true
        // as dashed-red with a legend — no component change needed).
        edges.push({ from, to: pathOnly, broken: true });
      }
    }
  }
  return edges;
}

/**
 * Resolve a link target to an existing file path (mirrors findDanglingLinks's
 * exists() probe semantics): the exact path if it is a file, else the
 * `<path>.md` probe (the extensionless [[wikilink]] form). Returns the
 * resolved absolute path, or null when nothing resolves. Directories never
 * resolve (a concept is a .md file).
 */
async function resolveTarget(resolved) {
  try {
    const s = await stat(resolved);
    if (s.isFile()) return resolved;
  } catch {
    // fall through to the .md probe
  }
  try {
    const s = await stat(`${resolved}.md`);
    if (s.isFile()) return `${resolved}.md`;
  } catch {
    // not found
  }
  return null;
}

function stripCode(body) {
  return body
    .replace(/```[\s\S]*?```/g, "")
    .replace(/~~~[\s\S]*?~~~/g, "")
    .replace(/`[^`\n]*`/g, "");
}

function extractLinkTargets(body) {
  const out = [];
  for (const m of body.matchAll(/\[([^\]]*)\]\(([^)]+)\)/g)) out.push(m[2]);
  for (const m of body.matchAll(/\[\[([^\]]+)\]\]/g)) out.push(m[1].split("|")[0]);
  return out;
}

function isInternal(target) {
  const t = target.trim();
  if (/^(https?:|mailto:|tel:|ftp:)/i.test(t)) return false;
  if (t.startsWith("#")) return false;
  return true;
}

function targetPath(target) {
  let p = target.trim().split(/\s+/)[0] ?? "";
  p = p.replace(/^<|>$/g, "");
  p = p.split("#")[0];
  return p.trim();
}

async function exists(resolved) {
  try {
    const s = await stat(resolved);
    if (s.isDirectory() || s.isFile()) return true;
  } catch {
    // fall through to .md probe
  }
  try {
    await stat(`${resolved}.md`);
    return true;
  } catch {
    return false;
  }
}

function formatDangling(dangling) {
  const shown = dangling.slice(0, 5).map((d) => `${d.file} → ${d.target}`);
  const head = `${dangling.length} dangling: ${shown.join(", ")}`;
  return dangling.length > 5 ? `${head}, +${dangling.length - 5} more` : head;
}

/**
 * Check #5 — structural identity (D-02, D-08). Wraps verifyBundle: returns
 * {passed:false, reason:'structure: ...'} on the first failing IDENTITY check
 * (quality warnings never block — D-09), else {passed:true, reason:'...'}.
 * The detail is sanitized (T-07-INJECT) since it carries user-controlled paths.
 *
 * @param {{manifest?: object, bundleDir: string}} args
 * @returns {Promise<{passed: boolean, reason: string}>}
 */
export async function checkStructure({ bundleDir }) {
  const { checks } = await verifyBundle(bundleDir);
  const firstFail = checks.find((c) => c.severity === "identity" && c.status === "fail");
  if (firstFail) {
    const detail = firstFail.detail ? ` — ${sanitizeForComment(firstFail.detail)}` : "";
    return {
      passed: false,
      reason: `structure: ${firstFail.name} failed${detail}`,
    };
  }
  return { passed: true, reason: "structure: bundle passes identity checks." };
}

// PHASE 10 (D-03): expose the link-resolution internals extractGraphEdges is
// built on, so the graph build never re-implements link semantics (10-01-PLAN
// prohibition: "MUST NOT reinvent link extraction").
export { extractLinkTargets, findDanglingLinks };

// Keep the __dirname reference live (anchors module resolution even if a future
// edit drops the import); no runtime cost.
void __dirname;
