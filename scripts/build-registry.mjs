#!/usr/bin/env node
// Registry aggregator — validates every manifest, computes structural-conformance
// evidence INLINE, and writes a flat registry.json.
//
// Run:  npm ci && (cd scripts/checks && npm ci) && node scripts/build-registry.mjs
//
// Reads every `*.json` manifest under every `io.github.*/` namespace dir in
// this repo (io.github.google/, io.github.asagajda/, any io.github.<login>/),
// validates each against the vendored ManifestSchema, clones its source to run
// verifyBundle (the D-03 single source of truth), embeds the resulting evidence
// directly into the bundle object, and emits a flat
// `{ generated_at, count, bundles: Manifest[] }` at the repo root. The GitHub
// Action (.github/workflows/build-registry.yml) commits that file cross-repo
// into okfhub-website/public/registry.json.
//
// EVIDENCE INLINE (Phase 4, Option A — D-04 adapted): evidence is computed fresh
// on every build rather than read from git-tracked sidecars. The sidecar design
// was abandoned because protected `main` rejects the App's direct sidecar push
// (required_status_checks blocks direct pushes regardless of bypass — verified
// empirically with both classic protection GH006 and Rulesets GH013). Inline
// compute routes evidence through the already-working registry.json → website
// channel, touching no protected branch. Trade-off: evidence is no longer a
// standalone git-tracked sidecar, but it IS git-tracked inside registry.json
// (in the website repo) and is always freshly recomputed (T-09-TAMPER improved).
//
// On any validation error the script exits 1 with a list of the bad files — a
// publish-time guard so a malformed manifest can never reach the index.

import { readdir, readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
// Evidence pipeline (inline compute — Option A). verifyBundle is the D-03
// single source of truth; cloneAndExtract is the hardened source fetcher. Both
// live in scripts/checks/ and are imported here so the aggregator recomputes
// evidence fresh on every build (no git-tracked sidecar read).
// PHASE 5: parseBundle is ALSO imported — computeEvidence now materializes
// concept bodies (D-04) from the SAME walk verifyBundle uses, so evidence and
// the live read pin to the same resolved_sha (Phase-4 D-06 consistency).
// PHASE 10 (D-03): extractGraphEdges reuses structure.mjs's link-resolution
// logic (extractLinkTargets + the T-10-01 escape guard) to emit resolved +
// broken concept-graph edges. findDanglingLinks stays untouched (it still
// feeds the links-resolve warn check).
import { verifyBundle, parseBundle, extractGraphEdges } from "./checks/structure.mjs";
// PHASE 10 (D-03): re-export so the graph build + its tests import from one
// module. extractGraphEdges itself is defined in checks/structure.mjs (it
// reuses findDanglingLinks's resolution logic verbatim).
export { extractGraphEdges };
import { cloneAndExtract } from "./checks/clone-source.mjs";
import { sanitizeForComment } from "./checks/gate-lib.mjs";
// paid-01 (whole-repo model): pro/ is RESERVED paid territory in EVERY bundle.
// The publisher's private pro_source repo IS the paid layer and lands under
// pro/ in a buyer's install (one repo ↔ one folder), so nothing from any
// bundle's pro/ tree is ever materialized, graphed, or trust-rolled-up.
function isReservedProPath(relPath) {
  const norm = String(relPath).replace(/\\/g, "/");
  return norm === "pro" || norm.startsWith("pro/");
}
// PHASE 7 (D-02): publisher reputation compute — attached to the bundle as a
// SIBLING to `evidence` (NOT folded into evidence.checks[]). Computed fresh on
// every build (D-06); never uses the smartReupdate cron-carry-forward path.
import { computeReputation } from "./checks/reputation.mjs";
// PHASE 8 (HTTP-02/HTTP-03): the build-side HTTP fetcher twin + the DNS TXT
// challenge resolver. fetchHttpSource is imported from the BUILD-SIDE relative
// path (./checks/fetch-http-source.mjs — the vendored twin from Plan 02), NOT
// from okfhub-cli/src/lib/source.ts (an unresolvable cross-repo TS import).
// Returns the SAME { extractDir, bundleDir, resolvedRef } contract as
// cloneAndExtract, with resolvedRef = content SHA (D-06). dnsVerify is the
// never-throw DNS verification entry point (dns-verified-domain/dns-stale/dns-pending).
import { fetchHttpSource } from "./checks/fetch-http-source.mjs";
import { dnsVerify } from "./checks/dns-verify.mjs";

// VENDORED from okfhub-cli/src/lib/manifest.ts — keep in sync (CLI is source of truth).
// Phase 1 of the manifest schema (ManifestSchema + SourceSchema). Byte-identical
// field list + constraints so the registry, the CLI, and the website all bind to
// one contract.

export const SourceType = z.enum(["github", "git", "tarball", "http"]);

export const SourceSchema = z.object({
  type: SourceType,
  url: z.string().url(),
  path: z.string().default(""),
  ref: z.string().default("main"),
});

export const ManifestSchema = z.object({
  schema_version: z.literal(1),
  // WR-07: constrain name to the resolver's lowercase-kebab shape. The namespace
  // is regex-anchored but name was only z.string().min(1), so a manifest name
  // like "../../public/registry" would let join(CONCEPTS_DIR, ns, name, relPath)
  // collapse the ".." and write outside concepts/. Mirror the namespace shape.
  name: z.string().regex(/^[a-z0-9-]+$/, "name must be lowercase-kebab (a-z, 0-9, -) only"),
  namespace: z.string().regex(/^io\.(github|http)\.[a-z0-9.-]+$/),
  description: z.string(),
  version: z.string(),
  source: SourceSchema,
  kind: z.enum(["knowledge", "webapp"]).default("knowledge"),
  categories: z.array(z.string()).default([]),
  license: z.string().optional(),
  homepage: z.string().url().optional(),
});

// Scan EVERY io.github.* namespace directory, not just io.github.google. The
// D-20 fix updated the trigger's paths filter to `io.github.*/*.json` so
// external publishes (io.github.asagajda/, io.github.<any-login>/) fire the
// build — but if the aggregator only reads io.github.google/, external
// manifests trigger a build that then ignores them. Phase 3's self-publishing
// feature relies on this being consistent: trigger + discovery must cover the
// same set of namespaces. Phase 8 adds io.http.<domain>/ (HTTP-served bundles).
const NAMESPACE_GLOBS = ["io.github.*", "io.http.*"];
const OUTPUT = "registry.json";

// Bump whenever a check's logic changes — recorded in each evidence object so a
// future consumer can tell whether two evidence snapshots are comparable.
const CHECK_LOGIC_VERSION = 1;

/**
 * Materialize a bundle's concept bodies into artifact records (Phase 5, D-04).
 * Calls parseBundle (the SAME vendored walk verifyBundle uses) and maps each
 * concept to `{ relPath, type, body }` where `body` is the raw markdown text
 * (frontmatter + content) that becomes the MCP `text/markdown` resource (D-05).
 *
 * PURE: reads bundleDir only — no network, no eval (T-06-PAWN — text read only).
 * Symlink concept files are rejected by parseBundle's walkMd (T-04-SYM). A
 * bundle with zero concepts yields an empty array (never errors). Exported so
 * the materialization logic is unit-testable without a network clone — mirrors
 * how verifyBundle/parseBundle are pure exported helpers tested with local dirs.
 *
 * @param {string} bundleDir - the extracted bundle root (same dir verifyBundle reads)
 * @returns {Promise<Array<{relPath: string, type: string, body: string}>>}
 */
export async function materializeConcepts(bundleDir) {
  const { concepts } = await parseBundle(bundleDir);
  // PHASE 10 (D-03): also carry the parsed frontmatter object so buildGraph can
  // populate GraphNode title/tags/desc. Additive — the gateway only consumes
  // {relPath, body}; existing callers ignore the extra field.
  //
  // PHASE 10 (D-06): the SAME frontmatter object already carries the OKF v0.2
  // families when present — generated {by, at}, verified [{by, at}],
  // stale_after, status, sources — because parseBundle's ConceptFrontmatter
  // schema is .passthrough() (structure.mjs:35-37). summarizeTrustBundle only
  // READS them (never re-parses, never extends the schema — v0.2 is
  // permissive: a concept missing any family is never rejected).
  return concepts.map((c) => ({
    relPath: c.relPath,
    type: c.type,
    body: c.body,
    frontmatter: c.frontmatter,
  }));
}

// ---------------------------------------------------------------------------
// PHASE 10 (D-03 + D-08) — the concept-graph build + OpenWiki trace detection.
// Both ride the EXISTING materializeConcepts walk (Option A: compute inline at
// build, never re-walk the tree). The graph flows:
//   extractGraphEdges (structure.mjs) → buildGraph → emitGraphs → graphs.json
//   → cross-repo push → okfhub-website/lib/graph.ts loadGraph → ConceptGraph.
// ---------------------------------------------------------------------------

// The SVG viewport ConceptGraph.tsx renders into (viewBox "0 0 920 480").
// Layout coordinates are computed at build time (deterministic — no runtime
// force simulation in the component) so the same input always renders the
// same picture.
const GRAPH_VIEW = { w: 920, h: 480 };

/** Deterministic radial "force" layout: index-ish node centered, the rest on
 *  concentric rings. Unique positions by construction (no two nodes overlap). */
function forcePositions(count) {
  const cx = GRAPH_VIEW.w / 2;
  const cy = GRAPH_VIEW.h / 2;
  const positions = [];
  if (count === 0) return positions;
  positions.push([cx, cy]);
  let placed = 1;
  let ring = 1;
  while (placed < count) {
    const radius = Math.min(70 * ring, Math.min(cx, cy) - 40);
    const onRing = Math.min(count - placed, Math.max(6, Math.floor((2 * Math.PI * radius) / 56)));
    for (let i = 0; i < onRing; i++) {
      const angle = (2 * Math.PI * i) / onRing + ring * 0.35; // ring phase offset
      positions.push([
        Math.round((cx + radius * Math.cos(angle)) * 10) / 10,
        Math.round((cy + radius * Math.sin(angle)) * 10) / 10,
      ]);
    }
    placed += onRing;
    ring += 1;
  }
  return positions;
}

/** Deterministic "by path" hierarchy layout: depth = row, siblings spread
 *  across the row. Unique positions by construction. */
function hierPositions(relPaths) {
  const byDepth = new Map(); // depth → [sortIndex,...]
  relPaths.forEach((relPath, i) => {
    const depth = relPath.split("/").length - 1;
    if (!byDepth.has(depth)) byDepth.set(depth, []);
    byDepth.get(depth).push(i);
  });
  const positions = new Array(relPaths.length);
  const depths = [...byDepth.keys()].sort((a, b) => a - b);
  depths.forEach((depth) => {
    const row = byDepth.get(depth);
    const y = Math.min(70 + depth * 90, GRAPH_VIEW.h - 40);
    row.forEach((idx, col) => {
      const x = Math.round(((GRAPH_VIEW.w - 120) * (col + 1)) / (row.length + 1)) + 60;
      positions[idx] = [x, y];
    });
  });
  return positions;
}

/** Frontmatter → GraphNode scalar coercion. The website renders every field as
 *  escaped React text, so user-controlled frontmatter is data only here — but
 *  coerce to strings/empty so a malformed frontmatter can never emit a
 *  non-serializable graph (never-throw discipline). */
function fmString(v) {
  if (typeof v === "string") return v;
  if (Array.isArray(v)) return v.filter((x) => typeof x === "string").join(", ");
  return v == null ? "" : String(v);
}

/**
 * Build one bundle's ConceptGraph (the {NODES, EDGES} shape of
 * okfhub-website/lib/types.ts GraphNode/GraphEdge/ConceptGraph).
 *
 * NODES: one per materialized concept — id = relPath minus the .md suffix,
 * type/path/title/tags/desc from frontmatter, deterministic force/hier layout
 * coordinates. EDGES: the extractGraphEdges output mapped to [from, to, true?]
 * tuples (3rd element true = broken — ConceptGraph.tsx renders dashed-red).
 *
 * PURE over its inputs (no fs) — unit-testable with synthetic concepts/edges.
 *
 * @param {Array<{relPath: string, type: string, frontmatter?: object}>} concepts
 * @param {Array<{from: string, to: string, broken?: boolean}>} edges
 * @returns {{NODES: object[], EDGES: Array<[string, string, true?]>}}
 */
export function buildGraph(concepts, edges) {
  const relPaths = concepts.map((c) => c.relPath);
  const force = forcePositions(concepts.length);
  const hier = hierPositions(relPaths);
  const NODES = concepts.map((c, i) => {
    const fm = c.frontmatter ?? {};
    return {
      id: c.relPath.replace(/\.md$/, ""),
      type: fmString(c.type),
      path: c.relPath,
      title: fmString(fm.title),
      tags: fmString(fm.tags),
      desc: fmString(fm.description),
      force: force[i],
      hier: hier[i],
    };
  });
  const EDGES = edges.map((e) => (e.broken ? [e.from, e.to, true] : [e.from, e.to]));

  // Broken-edge targets get an `unresolved: true` placeholder NODE so
  // ConceptGraph.tsx can render them: the edge draw skips any endpoint not in
  // nodeById (L72-73), and the dashed-red broken rendering + legend (L31, L82-84)
  // + the Inspector's red "unresolved" badge all key off the placeholder node.
  // Placeholder ids are deduped + appended AFTER the real nodes so the real
  // nodes keep their deterministic layout slots. The target string is
  // bundle-author-controlled DATA (rendered escaped by React — never resolved).
  const known = new Set(NODES.map((n) => n.id));
  const extras = [];
  for (const e of edges) {
    if (!e.broken) continue;
    const id = String(e.to).replace(/\.md$/, "");
    if (known.has(id)) continue;
    known.add(id);
    extras.push(id);
  }
  const extraForce = forcePositions(NODES.length + extras.length).slice(NODES.length);
  const extraHier = hierPositions([...relPaths, ...extras.map((id) => `${id}.md`)]).slice(NODES.length);
  extras.forEach((id, i) => {
    NODES.push({
      id,
      type: "page",
      path: id, // the target as written (inert label data — never resolved)
      title: id,
      tags: "",
      desc: "",
      force: extraForce[i],
      hier: extraHier[i],
      unresolved: true,
    });
  });

  return { NODES, EDGES };
}

/**
 * PHASE 10 (D-08): OpenWiki trace detection. OpenWiki (langchain-ai/openwiki)
 * stamps a `<!-- OPENWIKI:START -->…<!-- OPENWIKI:END -->` marker comment
 * around the block it rewrites on each run. Detection is repo-level: ANY
 * materialized concept body carrying the START marker flips the additive
 * `openwiki_detected` boolean on the bundle. Detection only — NO integration.
 *
 * PURE over its inputs (no fs, never throws on an empty set).
 *
 * @param {Array<{body?: string}>} artifacts - materializeConcepts output
 * @returns {boolean}
 */
export function detectOpenwiki(artifacts) {
  if (!Array.isArray(artifacts)) return false;
  return artifacts.some((a) => typeof a?.body === "string" && a.body.includes("<!-- OPENWIKI:START -->"));
}

// ---------------------------------------------------------------------------
// PHASE 10 (D-06) — OKF v0.2 content-trust read-path (Layer 1). The build
// reads the additive v0.2 concept frontmatter families (generated/verified/
// stale_after/status/sources) WHEN PRESENT — they are ALREADY preserved by
// parseBundle's .passthrough() ConceptFrontmatter (structure.mjs:35-37), so
// this is purely READ code: NO ConceptFrontmatter schema change, NO CLI
// ManifestSchema change (the D-06 guardrail — v0.2 is a strict superset and
// "consumers MUST NOT reject a concept for missing any optional family").
//
// summarizeTrustBundle is a deliberate MIRROR of the website's lib/trust.ts
// summarizeTrust (the canonical pure consumer): registry-repo cannot import
// the website's TS module, so the build emits the same TrustSummary shape
// into registry.json (bundle.trust_summary) and the website re-derives at
// render if it needs to. Keep the two in sync — the roll-up logic (tier
// counts + dated-evidence rows, neutral glyphs only, never a 🟢/🔵/🟡 badge
// per D-09) is identical by construction-test (tests/build-registry-trust).
// ---------------------------------------------------------------------------

/** Derive one concept's trust tier — mirror of lib/trust.ts deriveConceptTier
 *  (OKF v0.2 spec §5.3). Never throws on malformed frontmatter. */
function deriveConceptTierBuild(frontmatter) {
  const fm = frontmatter && typeof frontmatter === "object" ? frontmatter : undefined;
  const verified = fm?.verified;
  if (!fm || !Array.isArray(verified) || verified.length === 0) return "unverified";
  let sawEntry = false;
  for (const v of verified) {
    if (!v || typeof v !== "object") continue;
    sawEntry = true;
    if (typeof v.by === "string" && v.by.startsWith("human:")) return "human-reviewed";
  }
  return sawEntry ? "machine-confirmed" : "unverified";
}

/** Freshness from stale_after — mirror of lib/trust.ts deriveFreshness.
 *  Absent/unparseable → "unknown", never throws. */
function deriveFreshnessBuild(staleAfterIso, now = new Date()) {
  if (!staleAfterIso || typeof staleAfterIso !== "string") return "unknown";
  const d = Date.parse(staleAfterIso);
  if (Number.isNaN(d)) return "unknown";
  return d < now.getTime() ? "stale" : "fresh";
}

/** Coerce an author-controlled frontmatter value to display text. js-yaml
 *  parses unquoted YAML dates (e.g. `at: 2026-08-06`) as Date objects —
 *  normalize those to ISO so rows stay machine-readable. */
function trustAsText(v) {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (v instanceof Date) return v.toISOString();
  return String(v);
}

/**
 * PHASE 10 (D-06): roll the materialized concepts' v0.2 frontmatter up into
 * the bundle-level trust_summary (the TrustSummary shape of
 * okfhub-website/lib/types.ts — flat tier counts + tier_counts + dated-
 * evidence rows with neutral glyphs only). Rides the existing
 * materializeConcepts artifacts (no re-walk); reads each concept's parsed
 * frontmatter (already populated by parseBundle's .passthrough()).
 *
 * PERMISSIVE: a concept missing any v0.2 family counts as "unverified" and
 * contributes the honest absence row — NEVER rejected, NEVER undefined,
 * NEVER an error (spec mandate; mirrors the website's never-throw contract).
 * A malformed family (e.g. `verified: "garbage"`) degrades that ONE concept
 * to unverified without aborting the roll-up.
 *
 * PURE over its inputs (no fs) — unit-testable with materialized artifacts.
 *
 * @param {Array<{frontmatter?: object}>} artifacts - materializeConcepts output
 * @param {Date} [now] - derivation clock (tests pin it; production = build time)
 * @returns {{trust_logic_version: 1, checked_at: string, total: number,
 *   unverified: number, machineConfirmed: number, humanReviewed: number,
 *   tier_counts: {unverified: number, machineConfirmed: number, humanReviewed: number},
 *   generated?: {by?: string, at?: string},
 *   freshness?: {stale_after?: string, status: string},
 *   rows: Array<{glyph: string, text: string, dateIso?: string}>}}
 */
export function summarizeTrustBundle(artifacts, now = new Date()) {
  const list = Array.isArray(artifacts) ? artifacts : [];
  let unverified = 0;
  let machineConfirmed = 0;
  let humanReviewed = 0;
  const rows = [];
  const seen = new Set();
  let generated;
  let earliestStaleAfter;

  const pushOnce = (row) => {
    const key = `${row.glyph}|${row.text}`;
    if (seen.has(key)) return;
    seen.add(key);
    rows.push(row);
  };

  for (const artifact of list) {
    let tier = "unverified";
    let gen;
    let verified = [];
    let staleAfter;
    try {
      const fm =
        artifact?.frontmatter && typeof artifact.frontmatter === "object"
          ? artifact.frontmatter
          : undefined;
      tier = deriveConceptTierBuild(fm);
      gen = fm?.generated && typeof fm.generated === "object" ? fm.generated : undefined;
      verified = Array.isArray(fm?.verified)
        ? fm.verified.filter((v) => v != null && typeof v === "object")
        : [];
      const rawStale = fm?.stale_after;
      staleAfter =
        typeof rawStale === "string"
          ? rawStale
          : rawStale instanceof Date
            ? rawStale.toISOString()
            : undefined;
    } catch {
      // One pathological concept never blocks the roll-up — degrade it.
      tier = "unverified";
      gen = undefined;
      verified = [];
      staleAfter = undefined;
    }

    if (tier === "human-reviewed") humanReviewed += 1;
    else if (tier === "machine-confirmed") machineConfirmed += 1;
    else unverified += 1;

    // ℹ generated by <agent> · <date>
    if (gen && (gen.by != null || gen.at != null)) {
      const by = trustAsText(gen.by);
      const at = trustAsText(gen.at);
      if (!generated) generated = { ...(by && { by }), ...(at && { at }) };
      pushOnce({
        glyph: "info",
        text: at ? `generated by ${by} · ${at}` : `generated by ${by}`,
        ...(at && { dateIso: at }),
      });
    }

    // ℹ verified by <actor> · <date> — one row per distinct verifier.
    for (const v of verified) {
      const by = trustAsText(v.by);
      const at = trustAsText(v.at);
      pushOnce({
        glyph: "info",
        text: at ? `verified by ${by} · ${at}` : `verified by ${by}`,
        ...(at && { dateIso: at }),
      });
    }

    // Freshness: track the earliest parseable stale_after across concepts.
    if (staleAfter !== undefined) {
      const t = Date.parse(staleAfter);
      if (!Number.isNaN(t)) {
        if (!earliestStaleAfter || t < earliestStaleAfter.t) {
          earliestStaleAfter = { iso: staleAfter, t };
        }
      }
    }
  }

  // — N concepts with no verification frontmatter (honest absence, D-09).
  if (list.length === 0) {
    pushOnce({ glyph: "none", text: "no concepts indexed — no verification frontmatter" });
  } else if (unverified > 0) {
    pushOnce({
      glyph: "none",
      text:
        unverified === 1
          ? "1 concept with no verification frontmatter"
          : `${unverified} concepts with no verification frontmatter`,
    });
  }

  // ⏱ stale_after <date> · status: <stale|fresh|unknown>
  let freshness;
  if (earliestStaleAfter) {
    const status = deriveFreshnessBuild(earliestStaleAfter.iso, now);
    freshness = { stale_after: earliestStaleAfter.iso, status };
    pushOnce({
      glyph: "clock",
      text: `stale_after ${earliestStaleAfter.iso} · status: ${status}`,
      dateIso: earliestStaleAfter.iso,
    });
  }

  const total = list.length;
  return {
    trust_logic_version: 1,
    checked_at: now.toISOString(),
    total,
    unverified,
    machineConfirmed,
    humanReviewed,
    tier_counts: { unverified, machineConfirmed, humanReviewed },
    ...(generated && { generated }),
    ...(freshness && { freshness }),
    rows,
  };
}

/**
 * Compute the D-10 evidence object for a manifest INLINE (Option A — no sidecar
 * read). Clones the public source, runs verifyBundle (5 checks), appends
 * source-reachable (the 6th — pass since the tarball GET succeeded), and returns
 * the manifest with `evidence` set + `source` resolved-sha metadata.
 *
 * PHASE 5 (D-04): also materializes concept bodies via parseBundle inside the
 * same try block (after verifyBundle, before the finally cleanup), embedding a
 * `conceptArtifacts` array on the returned bundle. Because materialization runs
 * against the SAME extracted bundleDir as verifyBundle, evidence and the live
 * read are about the SAME pinned resolved_sha (Phase-4 D-06 consistency).
 *
 * Clones only PUBLIC source repos and runs verifyBundle which reads markdown
 * only — never eval/execs bundle files (T-06-PAWN). Every detail string is
 * sanitized (T-07-INJECT) since it can carry user-controlled bundle file paths.
 *
 * @param {object} manifest - the validated manifest (result.data)
 * @param {string} manifestPath - its repo-relative path (for warnings only)
 * @param {{clone?: Function}} [opts] - optional clone override for unit tests
 *   (default: the real cloneAndExtract). The override must return
 *   `{ extractDir, bundleDir, resolvedRef }`. Production always uses the default.
 * @returns {Promise<{bundle: object, warning?: string}>} the manifest with
 *   `evidence` (the D-10 object), `source` ({resolved_sha}), and
 *   `conceptArtifacts` embedded, or the bare manifest with a warning if the
 *   source clone/verify failed (one bad bundle must never block the whole index
 *   — it stays evidence-pending AND concept-pending).
 */
export async function computeEvidence(manifest, manifestPath, opts = {}) {
  // PHASE 8 (HTTP-02/HTTP-03): dispatch on source.type. The github branch is
  // UNCHANGED (clone → verifyBundle → materializeConcepts → computeReputation).
  // The http branch runs fetchHttpSource (the build-side twin, injected via
  // opts.fetchHttp for tests) → verifyBundle (UNCHANGED — pure, source-agnostic)
  // → dnsVerify (the DNS TXT challenge, opts.resolver threads through) →
  // computeReputation (the http branch inside reputation.mjs emits the dated
  // dns-verified-domain/dns-stale signal from the threaded dnsResult). A DNS
  // verify failure degrades the bundle to dns-pending WITHOUT aborting the
  // build (the per-bundle try/catch stays — one bad bundle never blocks the index).
  if (manifest.source?.type === "http") {
    return computeHttpEvidence(manifest, manifestPath, opts);
  }
  if (!manifest.source || manifest.source.type !== "github") {
    return {
      bundle: { ...manifest },
      warning: `${manifestPath}: source type '${manifest.source?.type}' not supported (only 'github', 'http') — evidence skipped.`,
    };
  }
  // Production uses the real hardened clone; tests inject a local-dir resolver
  // so the success path is unit-testable without a network call (mirrors how the
  // existing tests cover only the non-network paths of computeEvidence).
  const clone = opts.clone ?? cloneAndExtract;
  try {
    const { owner, repo } = parseGithubUrl(manifest.source.url);
    const ref = manifest.source.ref ?? "main";
    const sourcePath = manifest.source.path ?? "";
    const { extractDir, bundleDir, resolvedRef } = await clone(owner, repo, ref, sourcePath);
    let checks;
    let conceptArtifacts;
    try {
      checks = (await verifyBundle(bundleDir)).checks;
      // D-04: materialize concept bodies from the SAME extracted dir, so the
      // gateway reads the exact pinned snapshot the evidence describes. Runs
      // AFTER verifyBundle (verify is the identity gate) and BEFORE the finally
      // rm(extractDir) cleanup — the bodies must be captured before teardown.
      conceptArtifacts = await materializeConcepts(bundleDir);
    } finally {
      const { rm } = await import("node:fs/promises");
      await rm(extractDir, { recursive: true, force: true });
    }
    // The 6th check (source-reachable) — pass since the tarball GET succeeded.
    checks.push({ id: "source-reachable", name: "Source repo reachable", severity: "quality", status: "pass" });
    // paid-01: the honest paid-layer row. "skipped" (excluded from check
    // counts) with the exact scope stated: gated concepts are DECLARED, kept
    // out of the public index, and evaluated only via the gateway behind a
    // license — never presented as publicly verified.
    if (manifest.paid) {
      checks.push({
        id: "paid-layer",
        name: "Paid layer",
        severity: "quality",
        status: "skipped",
        detail: `declared (provider ${manifest.paid.provider}); gated concepts excluded from the public index; served only by the okfhub gateway with a valid license`,
      });
    }
    // PHASE 7 (D-02/D-06): compute publisher reputation as a sibling step. Runs
    // AFTER the structural clone+verify succeed, BEFORE the return. Reputation
    // is independent of the clone (REST /repos + /users + /orgs, not the
    // extracted tree) and never throws — a fetch failure degrades to pending
    // (reputation undefined), never aborting the build (the per-bundle catch at
    // L182-188 still wraps this try block). opts.gh threads through so tests
    // can inject a mocked fetcher (mirrors the opts.clone override at L145).
    // priorReputation is undefined here per A-CF (the production path does not
    // yet wire a prior registry.json cross-repo read; the carry-forward branch
    // is implemented + unit-tested but ships as transient→pending).
    const repResult = await computeReputation(manifest, undefined, opts);
    // Reputation degrade (transient→pending / non-github skip) is non-fatal —
    // the bundle still ships with evidence intact. Surface the reason to the
    // build log WITHOUT overriding the evidence-warning contract (the returned
    // `warning` field means "evidence compute failed"; reputation pending is a
    // separate, known degradation).
    if (repResult.warning) console.warn(`⚠️ reputation: ${repResult.warning}`);
    return {
      bundle: {
        ...manifest,
        evidence: {
          evidence_version: 1,
          namespace: manifest.namespace,
          name: manifest.name,
          resolved_sha: resolvedRef,
          checked_at: new Date().toISOString(),
          check_logic_version: CHECK_LOGIC_VERSION,
          checks: sanitizeChecks(checks),
        },
        source: { resolved_sha: resolvedRef },
        conceptArtifacts,
        reputation: repResult.reputation,
        // PHASE 10 (D-06): the content-trust roll-up rides the SAME
        // materialization (additive sibling to evidence/reputation — the
        // CONTENT axis beside the PUBLISHER axis, never merged; D-09).
        trust_summary: safeTrustSummary(conceptArtifacts, manifestPath),
      },
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      bundle: { ...manifest },
      warning: `${manifestPath}: evidence compute failed (${msg}) — bundle stays evidence-pending.`,
    };
  }
}

/**
 * The http branch of computeEvidence (Phase 8, HTTP-02/HTTP-03). Mirrors the
 * github branch's structure but swaps cloneAndExtract → fetchHttpSource and
 * threads dnsVerify between verifyBundle and computeReputation:
 *   fetchHttpSource → verifyBundle (UNCHANGED) → dnsVerify → computeReputation(dns)
 *
 * verifyBundle is source-agnostic (reads bundleDir only) and runs IDENTICALLY for
 * http and github — no weaker validation path for HTTP (T-08-VERIFY, HTTP-04).
 * The DNS result is threaded into computeReputation via opts.dnsResult so its http
 * branch can emit the dated dns-verified-domain/dns-stale signal, and the
 * dns_verified_at is attached to the returned bundle (the dated-evidence anchor).
 *
 * A DNS verify failure degrades to dns-pending WITHOUT aborting — the dnsVerify
 * call is wrapped in its own try/catch inside the outer per-bundle catch, so a
 * bad DNS lookup flips the bundle's reputation to dns-pending but evidence + the
 * rest of the index still ship (T-08-ISOLATION: one bad bundle never blocks the index).
 *
 * @param {object} manifest - validated http-sourced manifest
 * @param {string} manifestPath - repo-relative path (warnings only)
 * @param {object} opts - { fetchHttp, resolver, dnsResult?, ...rest threaded to
 *   computeReputation }. opts.fetchHttp overrides fetchHttpSource for tests
 *   (mirrors opts.clone). opts.resolver threads through to dnsVerify (the Wave-0
 *   mock seam). opts.dnsResult is an OPTIONAL override (tests may inject the
 *   final DNS state directly; production derives it from dnsVerify).
 */
async function computeHttpEvidence(manifest, manifestPath, opts = {}) {
  // Production uses the build-side fetcher twin; tests inject a local-dir stub
  // via opts.fetchHttp (mirrors the opts.clone seam at L145). Both return the
  // SAME { extractDir, bundleDir, resolvedRef } contract.
  const fetchHttp = opts.fetchHttp ?? fetchHttpSource;
  try {
    const { extractDir, bundleDir, resolvedRef } = await fetchHttp(manifest, opts);
    let checks;
    let conceptArtifacts;
    try {
      // verifyBundle runs UNCHANGED (pure, source-agnostic — reads bundleDir
      // only). HTTP bundles are validated IDENTICALLY to GitHub bundles (HTTP-04).
      checks = (await verifyBundle(bundleDir)).checks;
      conceptArtifacts = await materializeConcepts(bundleDir);
    } finally {
      const { rm } = await import("node:fs/promises");
      await rm(extractDir, { recursive: true, force: true });
    }
    // The 6th check (source-reachable) — pass since the tarball GET succeeded.
    checks.push({ id: "source-reachable", name: "Source repo reachable", severity: "quality", status: "pass" });
    // paid-01: the honest paid-layer row. "skipped" (excluded from check
    // counts) with the exact scope stated: gated concepts are DECLARED, kept
    // out of the public index, and evaluated only via the gateway behind a
    // license — never presented as publicly verified.
    if (manifest.paid) {
      checks.push({
        id: "paid-layer",
        name: "Paid layer",
        severity: "quality",
        status: "skipped",
        detail: `declared (provider ${manifest.paid.provider}); gated concepts excluded from the public index; served only by the okfhub gateway with a valid license`,
      });
    }

    // PHASE 8 (HTTP-02): run the DNS TXT challenge (never-throw). opts.resolver
    // threads through for tests (the Wave-0 mock seam). A DNS failure degrades
    // to dns-pending (state) but does NOT abort — the outer catch only fires on
    // fetch/verify failures. priorBlock (the prior build's dns_verified_at) is
    // undefined here per A-CF (same as github reputation); the carry-forward /
    // stale detection is implemented + unit-tested in dns-verify.mjs.
    let dnsResult = opts.dnsResult;
    let dnsWarning;
    if (!dnsResult) {
      try {
        dnsResult = await dnsVerify(manifest, undefined, opts);
      } catch (e) {
        // Never let a DNS failure abort the build — degrade to dns-pending.
        dnsResult = { state: "dns-pending", token: undefined };
        dnsWarning = e instanceof Error ? e.message : String(e);
      }
      if (dnsResult.warning) dnsWarning = dnsResult.warning;
    }

    // Thread the dnsResult into computeReputation so the http branch emits the
    // dated dns-verified-domain/dns-stale signal. Also thread the prior DNS
    // block (derived from dnsResult.dns_verified_at) for the stale-state date.
    const priorDnsBlock =
      typeof dnsResult.dns_verified_at === "string"
        ? { dns_verified_at: dnsResult.dns_verified_at }
        : undefined;
    const repResult = await computeReputation(manifest, undefined, {
      ...opts,
      dnsResult,
      priorDnsBlock,
    });
    if (repResult.warning) console.warn(`⚠️ reputation: ${repResult.warning}`);
    if (dnsWarning) console.warn(`⚠️ dns: ${dnsWarning}`);

    return {
      bundle: {
        ...manifest,
        evidence: {
          evidence_version: 1,
          namespace: manifest.namespace,
          name: manifest.name,
          resolved_sha: resolvedRef,
          checked_at: new Date().toISOString(),
          check_logic_version: CHECK_LOGIC_VERSION,
          checks: sanitizeChecks(checks),
        },
        source: { resolved_sha: resolvedRef },
        conceptArtifacts,
        reputation: repResult.reputation,
        // PHASE 10 (D-06): content-trust roll-up — identical contract to the
        // github branch (additive, permissive, never aborts).
        trust_summary: safeTrustSummary(conceptArtifacts, manifestPath),
        // The dated-evidence anchor (HTTP-03). Present only when the DNS
        // challenge passed or was carried forward within the 30d window.
        ...(dnsResult.dns_verified_at && { dns_verified_at: dnsResult.dns_verified_at }),
      },
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      bundle: { ...manifest },
      warning: `${manifestPath}: evidence compute failed (${msg}) — bundle stays evidence-pending.`,
    };
  }
}

/**
 * PHASE 10 (D-06): the per-bundle trust-summary compute guard. Wraps
 * summarizeTrustBundle so one pathological artifact set degrades to the
 * honest all-unverified summary (correct total — one empty frontmatter per
 * concept) instead of aborting the bundle build. Mirrors the "one bad bundle
 * never blocks the index" discipline (T-10-04 build-side).
 */
function safeTrustSummary(conceptArtifacts, label) {
  try {
    return summarizeTrustBundle(conceptArtifacts);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.warn(`⚠️ trust: ${label}: trust summary failed (${msg}) — degrading to all-unverified.`);
    const fallback = Array.isArray(conceptArtifacts)
      ? conceptArtifacts.map(() => ({ frontmatter: undefined }))
      : [];
    return summarizeTrustBundle(fallback);
  }
}

/** Parse owner/repo from a github source URL (mirrors source.ts parseGithubUrl). */
function parseGithubUrl(url) {
  const m = /^https:\/\/github\.com\/([^/]+)\/([^/?#]+?)(?:\.git)?(?:[/?#]|$)/.exec(url);
  if (!m) throw new Error(`source.url '${url}' is not a recognized GitHub URL.`);
  return { owner: m[1], repo: m[2] };
}

/** Sanitize every detail string in a checks array (T-07-INJECT). */
function sanitizeChecks(checks) {
  return checks.map((c) =>
    c.detail !== undefined ? { ...c, detail: sanitizeForComment(c.detail) } : { ...c },
  );
}

async function collectManifests() {
  const top = await readdir(".", { withFileTypes: true });
  const namespaceDirs = top
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .filter((name) => {
      // Match io.(github|http).<segment> — the namespace pattern the manifest
      // schema enforces (manifest.namespace regex). The http segment allows
      // dots+hyphens because it is a domain (e.g. io.http.example.com).
      return /^io\.(github|http)\.[a-z0-9.-]+$/.test(name);
    })
    .sort();
  const allFiles = [];
  for (const dir of namespaceDirs) {
    const entries = await readdir(dir, { recursive: true, withFileTypes: false });
    const files = entries
      .filter((f) => typeof f === "string" && f.endsWith(".json"))
      .map((f) => join(dir, f));
    allFiles.push(...files);
  }
  return allFiles.sort();
}

async function main() {
  const files = await collectManifests();
  const bundles = [];
  const errors = [];

  for (const rel of files) {
    let text;
    try {
      text = await readFile(rel, "utf8");
    } catch (e) {
      errors.push(`${rel}: could not read (${e instanceof Error ? e.message : String(e)})`);
      continue;
    }
    let json;
    try {
      json = JSON.parse(text);
    } catch (e) {
      errors.push(`${rel}: invalid JSON (${e instanceof Error ? e.message : String(e)})`);
      continue;
    }
    const result = ManifestSchema.safeParse(json);
    if (!result.success) {
      const issues = result.error.issues
        .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
        .join("; ");
      errors.push(`${rel}: ${issues}`);
      continue;
    }
    // D-04 (Phase 4, Option A — inline compute): clone the source, run
    // verifyBundle, and embed the fresh evidence object directly into the bundle.
    // A clone/verify failure is non-fatal — the bundle stays evidence-pending
    // (the website degrades to "pending" per Plan 04-02), but the index still ships.
    const { bundle: bundleObj, warning } = await computeEvidence(result.data, rel);
    if (warning) console.warn(`⚠️ evidence: ${warning}`);
    bundles.push({ ...bundleObj, __path: rel });
  }

  if (errors.length > 0) {
    console.error("❌ manifest validation failed:\n" + errors.join("\n"));
    process.exit(1);
  }

  // Defense-in-depth (audit finding): reject duplicate namespace+name entries.
  // The merge-gate now enforces namespace-field===path, but build-registry is
  // the LAST gate before the index ships — a duplicate here would mean two
  // files resolve to the same slug in registry.json (index pollution /
  // install ambiguity). Fail closed: if two manifests declare the same
  // namespace+name, the build fails rather than emitting a broken index.
  // Also cross-check that each manifest's declared namespace matches its
  // directory path (belt-and-braces alongside the gate's check).
  const seen = new Map(); // `${namespace}/${name}` → path
  for (const b of bundles) {
    const key = `${b.namespace}/${b.name}`;
    // namespace-field/path consistency (the path dir must equal the namespace).
    const pathOrg = b.__path.match(/^io\.github\.([a-z0-9-]+)\//)?.[1];
    if (pathOrg && pathOrg !== b.namespace.replace(/^io\.github\./, "")) {
      errors.push(`${b.__path}: namespace field '${b.namespace}' does not match its directory '${pathOrg}' (namespace/path mismatch).`);
      continue;
    }
    if (seen.has(key)) {
      errors.push(`${b.__path}: duplicate slug '${key}' (already declared at ${seen.get(key)}). Each namespace+name must be unique.`);
      continue;
    }
    seen.set(key, b.__path);
  }
  // Strip the internal __path marker before emitting.
  for (const b of bundles) delete b.__path;

  if (errors.length > 0) {
    console.error("❌ registry integrity check failed:\n" + errors.join("\n"));
    process.exit(1);
  }

  // Stable ordering: by namespace then name, so the generated registry.json has
  // a deterministic diff between runs regardless of readdir order.
  bundles.sort((a, b) =>
    `${a.namespace}/${a.name}`.localeCompare(`${b.namespace}/${b.name}`),
  );

  // PHASE 5 (D-04/D-05) — materialize concept bodies to a local concepts/ tree
  // BEFORE writing registry.json. RESEARCH Pitfall 6: the index must NEVER
  // advertise a bundle whose body is absent, so bodies are written first; if the
  // process dies between here and the registry.json write, the worst case is a
  // stale-but-present concepts/ tree (a re-run self-heals, since the pipeline
  // recomputes fresh every build — Phase 4 Option A).
  //
  // On-disk path mirrors the gateway read path (D-05): the concepts/ tree is
  // pushed cross-repo to okfhub-website/public/concepts/ and read via fs.readFile.
  // relPath already carries any subdirectory structure with POSIX slashes.
  // conceptArtifacts is a TRANSIENT compute-only field — stripped from the bundle
  // after writing so the bodies are NOT duplicated inside registry.json (the
  // gateway reads bodies from concepts/, never from the index).
  const CONCEPTS_DIR = "concepts";
  let totalMaterialized = 0;
  let totalGatedExcluded = 0;
  for (const b of bundles) {
    const artifacts = b.conceptArtifacts;
    if (!artifacts || artifacts.length === 0) continue;
    // paid-01 — LEAK EXCLUSION (the load-bearing rule of the paid layer):
    // pro/ is reserved territory in EVERY bundle (paid or not). The gated
    // content exists only in the publisher's private pro_source repo and is
    // served live by the gateway behind a license check; nothing under pro/
    // is ever written to the public concepts/ tree, the graphs, or the
    // public trust roll-up. The exclusion count is logged (visible,
    // auditable) — a bundle whose pro/ tree carries everything materializes
    // an index-only public build, which is the correct outcome.
    const publicArtifacts = artifacts.filter((a) => !isReservedProPath(a.relPath));
    const excluded = artifacts.length - publicArtifacts.length;
    if (excluded > 0) {
      totalGatedExcluded += excluded;
      const why = b.paid
        ? "paid layer"
        : "pro/ is reserved paid territory — declare a paid block to sell it";
      console.log(`🔒 excluded ${excluded} pro/ concept(s) from ${b.namespace}/${b.name} (${why})`);
    }
    for (const { relPath, body } of publicArtifacts) {
      // relPath is POSIX-normalized relative to bundleDir (from parseBundle's
      // readdir walk — already validated, no traversal). Join against the
      // {namespace}/{name} base; mkdir -p semantics create any nested dirs.
      const outPath = join(CONCEPTS_DIR, b.namespace, b.name, relPath);
      await mkdir(join(outPath, ".."), { recursive: true });
      await writeFile(outPath, body, "utf8");
    }
    totalMaterialized += publicArtifacts.length;
    if (publicArtifacts.length === 0) continue; // fully-gated bundle: index-only, nothing public to derive
    // PHASE 10 (D-08): OpenWiki trace detection rides the SAME materialized
    // artifacts (no re-walk). Additive boolean — bundles without the marker
    // carry openwiki_detected:false (explicit, so the website can distinguish
    // "scanned, not detected" from "never scanned" = field absent).
    // paid-01: computed over the PUBLIC artifacts only — gated content is not
    // scanned, described, or hinted at in the public index.
    b.openwiki_detected = detectOpenwiki(publicArtifacts);
    // PHASE 10 (D-06): refresh the content-trust roll-up from the SAME
    // materialized artifacts. computeEvidence already computed it; this is a
    // deterministic recompute (belt-and-braces so the shipped trust_summary
    // is always pinned to the artifacts actually written to concepts/). A
    // bundle with NO v0.2 frontmatter gets the honest all-unverified summary
    // here — never undefined, never an error (spec mandate: consumers MUST
    // NOT reject a concept for missing any optional family).
    // paid-01: pinned to the PUBLIC artifacts — trust_summary counts free
    // concepts only, which keeps its "total" honest against what's browsable.
    b.trust_summary = safeTrustSummary(publicArtifacts, `${b.namespace}/${b.name}`);
    console.log(`✅ materialized ${publicArtifacts.length} concepts for ${b.namespace}/${b.name}${b.openwiki_detected ? " (openwiki detected)" : ""}`);
  }
  // PHASE 10 (D-03): emit the sibling graphs.json — one ConceptGraph per
  // bundle ({NODES, EDGES}), keyed `${namespace}/${name}`, computed from the
  // SAME materialized artifacts (extractGraphEdges reads the concepts/ tree
  // just written above). SIBLING file, NOT embedded in registry.json — graph
  // data churn stays isolated from the per-page bundle index (T-10-03). Runs
  // BEFORE the conceptArtifacts strip so the artifacts are still present;
  // degrades per-bundle (a bundle whose artifacts are absent simply has no
  // graph entry — the website's loadGraph falls back to the honest empty
  // graph, never throws).
  const GRAPHS_OUTPUT = "graphs.json";
  const graphs = {};
  let totalGraphs = 0;
  for (const b of bundles) {
    const artifacts = b.conceptArtifacts;
    if (!artifacts || artifacts.length === 0) continue;
    // paid-01: graphs cover the PUBLIC set only — nothing under pro/ ever
    // appears as a node (its titles/paths would leak through the graph sidecar).
    const publicArtifacts = artifacts.filter((a) => !isReservedProPath(a.relPath));
    if (publicArtifacts.length === 0) continue; // fully-gated: no public graph
    const edges = await extractGraphEdges(join(CONCEPTS_DIR, b.namespace, b.name), publicArtifacts);
    graphs[`${b.namespace}/${b.name}`] = buildGraph(publicArtifacts, edges);
    totalGraphs += 1;
  }
  const graphsOutput = {
    generated_at: new Date().toISOString(),
    graphs_logic_version: 1,
    graphs,
  };
  await writeFile(GRAPHS_OUTPUT, JSON.stringify(graphsOutput, null, 2) + "\n", "utf8");
  console.log(`✅ emitted ${totalGraphs} concept graphs → ${GRAPHS_OUTPUT}`);
  if (totalGatedExcluded > 0) {
    console.log(`🔒 paid layer: ${totalGatedExcluded} gated concept(s) kept out of the public build in total`);
  }

  // Strip the transient conceptArtifacts payload — bodies live in concepts/, not
  // in the registry.json index (keeps registry.json lean; the gateway fs.readFile-s).
  //
  // WR-08: EXPLICIT contract — bundles WITHOUT conceptArtifacts intentionally
  // ship INDEX-ONLY. computeEvidence's graceful-degradation path (clone/verify
  // failure) returns `bundle: { ...manifest }` with NO conceptArtifacts key, and
  // the write loop above skips them (`if (!artifacts || artifacts.length === 0)
  // continue`). `delete` on a missing property is a benign no-op, so this second
  // loop is safe for both shapes. Such bundles are evidence-pending AND
  // concept-pending: they appear in registry.json (so callers can discover them)
  // but their concept bodies are NOT in concepts/, so a gateway resources/read
  // for them 404s via readFile (acceptable — the body was never materialized).
  // The index and the readable set are kept in lockstep by this skip: a bundle
  // is only in concepts/ if it reached the success path here.
  for (const b of bundles) delete b.conceptArtifacts;

  const output = {
    generated_at: new Date().toISOString(),
    count: bundles.length,
    bundles,
  };

  // RESEARCH Pitfall 6: registry.json is written AFTER the concepts/ tree above,
  // so the index never advertises a bundle whose body is missing on disk.
  await writeFile(OUTPUT, JSON.stringify(output, null, 2) + "\n", "utf8");
  console.log(`✅ aggregated ${bundles.length} bundles → ${OUTPUT}`);
}

// Run main() ONLY when this file is the entry point, not when imported (tests
// import embedEvidence directly).
import { fileURLToPath as __fileURLToPath } from "node:url";
const __isMain = process.argv[1] && __fileURLToPath(import.meta.url) === __fileURLToPath(new URL(`file://${process.argv[1]}`));
if (__isMain) {
  main().catch((e) => {
    console.error(`❌ build-registry failed: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  });
}
