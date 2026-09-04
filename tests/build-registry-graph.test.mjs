// build-registry-graph.test.mjs — D-03 concept-graph build tests (Phase 10,
// Plan 10-01). node:test + node:assert/strict + .mjs — MATCHES the existing
// registry .test.mjs files (NOT vitest — PATTERNS.md finding #10 Option A).
//
// Tests the D-03 graph-build slice:
//   - extractGraphEdges(bundleDir, concepts) reuses findDanglingLinks's
//     resolution logic (structure.mjs) and emits BOTH resolved edges and
//     broken edges ({from, to, broken:true}), rejecting bundle-dir escapes
//     via the SAME relative(bundleDir, resolved).startsWith("..") guard
//     (T-10-01 mitigate — the executable gate).
//   - buildGraph(concepts, edges) builds the NODES (one per concept .md,
//     id = relPath minus .md) + EDGES ([from, to, true?] tuples — the
//     GraphEdge shape okfhub-website/lib/types.ts:131 renders), with the
//     deterministic force/hier layout coordinates ConceptGraph.tsx consumes.
//   - The empty-fallback: one concept, no links → { NODES: [one], EDGES: [] }.
//
// FIXTURE DISCIPLINE: hermetic in-test tmp bundle dirs (mkdtemp + try/finally
// rm), exactly like build-registry-materialize.test.mjs — no committed fixture
// dependency, no network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { parseBundle } from "../scripts/checks/structure.mjs";
import { extractGraphEdges, buildGraph } from "../scripts/build-registry.mjs";

/** Build a tmp bundle dir with the given {relPath: content} files. Returns dir. */
async function makeBundle(files) {
  const dir = await mkdtemp(join(tmpdir(), "okfhub-graph-"));
  for (const [relPath, content] of Object.entries(files)) {
    const full = join(dir, relPath);
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content, "utf8");
  }
  return dir;
}

/** Concept body builder — frontmatter {type} + body. */
function concept(type, body = "") {
  return `---\ntype: ${type}\ntitle: t\ndescription: d\ntags: [x]\n---\n\n${body}\n`;
}

/** Parse a tmp bundle and return {dir, concepts} (parseBundle skips reserved files). */
async function parsedBundle(files) {
  const dir = await makeBundle(files);
  const { concepts } = await parseBundle(dir);
  return { dir, concepts };
}

test("graph: cross-linked bundle emits NODES + EDGES (both link forms)", async () => {
  // a.md links [b](b.md) (markdown form); c.md links [[a]] (wikilink form).
  // index.md is RESERVED (skipped by parseBundle) — NODES are the concepts.
  const { dir, concepts } = await parsedBundle({
    "index.md": "---\ntitle: idx\n---\n\n# Index\n",
    "a.md": concept("object", "See [b](b.md) for more."),
    "b.md": concept("metric", "B body."),
    "c.md": concept("object", "Back to [[a]]."),
  });
  try {
    const edges = await extractGraphEdges(dir, concepts);
    const graph = buildGraph(concepts, edges);

    const ids = graph.NODES.map((n) => n.id).sort();
    assert.deepEqual(ids, ["a", "b", "c"], "NODES = one per concept .md, id = relPath minus .md");

    // Every node carries the fields ConceptGraph.tsx consumes.
    for (const n of graph.NODES) {
      assert.ok(typeof n.path === "string" && n.path.endsWith(".md"));
      assert.ok(Array.isArray(n.force) && n.force.length === 2);
      assert.ok(Array.isArray(n.hier) && n.hier.length === 2);
      assert.ok(n.force.every(Number.isFinite) && n.hier.every(Number.isFinite));
    }

    // Resolved edges: a→b (markdown link) + c→a (wikilink), NOT marked broken.
    const hasAB = graph.EDGES.some((e) => e[0] === "a" && e[1] === "b" && e[2] !== true);
    const hasCA = graph.EDGES.some((e) => e[0] === "c" && e[1] === "a" && e[2] !== true);
    assert.ok(hasAB, "edge a→b from [text](path) form");
    assert.ok(hasCA, "edge c→a from [[wikilink]] form");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("graph: wikilink resolves the extensionless form against a sibling concept", async () => {
  // [[a]] has no .md suffix — resolution probes <resolved>.md (the same
  // exists() discipline as findDanglingLinks), so it resolves to a.md.
  const { dir, concepts } = await parsedBundle({
    "a.md": concept("object", "A body."),
    "b.md": concept("object", "Link [[a]]."),
  });
  try {
    const edges = await extractGraphEdges(dir, concepts);
    const graph = buildGraph(concepts, edges);
    const resolved = graph.EDGES.some((e) => e[0] === "b" && e[1] === "a" && e[2] !== true);
    assert.ok(resolved, "[[a]] resolves to a.md — edge b→a, not broken");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("graph: empty-fallback — one concept, no links → { NODES: [one], EDGES: [] }", async () => {
  const { dir, concepts } = await parsedBundle({
    "solo.md": concept("object", "No links here."),
  });
  try {
    const edges = await extractGraphEdges(dir, concepts);
    const graph = buildGraph(concepts, edges);
    assert.equal(graph.NODES.length, 1, "one NODE for the one concept");
    assert.deepEqual(graph.EDGES, [], "no links → empty EDGES (the honest empty-fallback)");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("graph: broken link emits [from, to, true] (ConceptGraph renders dashed-red)", async () => {
  // a.md links to a path that does not exist → broken edge (3rd element true).
  const { dir, concepts } = await parsedBundle({
    "a.md": concept("object", "See [ghost](missing.md)."),
  });
  try {
    const edges = await extractGraphEdges(dir, concepts);
    const graph = buildGraph(concepts, edges);
    const broken = graph.EDGES.find((e) => e[0] === "a" && e[2] === true);
    assert.ok(broken, "a broken edge is emitted with the 3rd element === true");
    assert.ok(typeof broken[1] === "string" && broken[1].length > 0, "the to-endpoint names the unresolved target");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("graph: path-escape is rejected (T-10-01 — no edge escaping the bundle dir)", async () => {
  // A malicious ../../../etc/passwd link MUST NOT resolve to a REAL edge
  // pointing outside the bundle. The relative(bundleDir, resolved).startsWith("..")
  // guard (findDanglingLinks's escape rejection, reused verbatim) blocks the
  // resolution; the attempt is surfaced as a BROKEN edge only.
  const { dir, concepts } = await parsedBundle({
    "a.md": concept("object", "Escape [x](../../../etc/passwd)."),
  });
  try {
    const edges = await extractGraphEdges(dir, concepts);
    const graph = buildGraph(concepts, edges);

    // THE GUARD: no RESOLVED edge exists — the escape never produced a real
    // from→to edge. The only edge is broken (broken edges render dashed-red
    // and carry no resolved target).
    const resolvedEdges = graph.EDGES.filter((e) => e[2] !== true);
    assert.equal(resolvedEdges.length, 0, "the escape MUST NOT emit a resolved edge");

    // The escape attempt is surfaced as BROKEN (dashed-red + legend), never
    // silently dropped and never resolved. The raw target rides along as inert
    // label data (rendered escaped by React — never a navigable/resolved path).
    const escape = graph.EDGES.find((e) => e[0] === "a");
    assert.ok(escape, "the escape attempt still emits an edge (broken)");
    assert.equal(escape[2], true, "the escape attempt is marked broken");

    // No node in the graph resolves to a path outside the bundle: every real
    // (non-unresolved) node path stays inside the bundle dir.
    for (const n of graph.NODES.filter((n) => !n.unresolved)) {
      assert.ok(!n.path.startsWith("/"), "no absolute-path node");
      assert.ok(!n.path.split("/").includes(".."), "no traversal in real node path");
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("graph: NODE coordinates are deterministic (same input → same layout)", async () => {
  const files = {
    "a.md": concept("object", "See [b](b.md)."),
    "b.md": concept("metric", "B."),
    "sub/c.md": concept("object", "See [[a]]."),
  };
  const first = await parsedBundle(files);
  const second = await parsedBundle(files);
  try {
    const g1 = buildGraph(first.concepts, await extractGraphEdges(first.dir, first.concepts));
    const g2 = buildGraph(second.concepts, await extractGraphEdges(second.dir, second.concepts));
    assert.deepEqual(g1, g2, "identical input produces byte-identical NODES + EDGES");
    // No two nodes share a position (the graph must actually spread out).
    const positions = g1.NODES.map((n) => `${n.force[0]},${n.force[1]}`);
    assert.equal(new Set(positions).size, positions.length, "force positions are unique");
  } finally {
    await rm(first.dir, { recursive: true, force: true });
    await rm(second.dir, { recursive: true, force: true });
  }
});
