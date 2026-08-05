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
import { verifyBundle, parseBundle } from "./checks/structure.mjs";
import { cloneAndExtract } from "./checks/clone-source.mjs";
import { sanitizeForComment } from "./checks/gate-lib.mjs";
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
  return concepts.map((c) => ({ relPath: c.relPath, type: c.type, body: c.body }));
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
  for (const b of bundles) {
    const artifacts = b.conceptArtifacts;
    if (!artifacts || artifacts.length === 0) continue;
    for (const { relPath, body } of artifacts) {
      // relPath is POSIX-normalized relative to bundleDir (from parseBundle's
      // readdir walk — already validated, no traversal). Join against the
      // {namespace}/{name} base; mkdir -p semantics create any nested dirs.
      const outPath = join(CONCEPTS_DIR, b.namespace, b.name, relPath);
      await mkdir(join(outPath, ".."), { recursive: true });
      await writeFile(outPath, body, "utf8");
    }
    totalMaterialized += artifacts.length;
    console.log(`✅ materialized ${artifacts.length} concepts for ${b.namespace}/${b.name}`);
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
