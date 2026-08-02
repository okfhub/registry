// build-registry-materialize.test.mjs — concept-body materialization tests (Phase 5,
// Plan 05-02, D-04/D-05). node:test + node:assert/strict + .mjs — MATCHES the 8
// existing registry .test.mjs files. NOT vitest (PATTERNS.md finding #10 Option A).
//
// Tests the materialization slice of the evidence pipeline:
//   - materializeConcepts(bundleDir) → conceptArtifacts[] with relPath/type/body
//   - symlink concept files are rejected (T-04-SYM)
//   - a bundle with zero concepts yields an empty conceptArtifacts array
//   - computeEvidence() embeds conceptArtifacts on the SUCCESS path (via an
//     injectable clone so the unit test does not hit the network)
//   - computeEvidence() OMITS conceptArtifacts on the graceful-degradation path
//     (one bad bundle never blocks the index — mirrors evidence graceful-degradation)
//
// FIXTURE DISCIPLINE: builds in-test tmp bundle dirs (mkdtemp), exactly like
// tests/checks/structure.test.mjs — no committed fixture file dependency, so the
// test is hermetic. The committed tests/fixtures/materialize-bundle/ files
// document the expected bundle shape but are not read at runtime.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm, symlink } from "node:fs/promises";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import {
  computeEvidence,
  materializeConcepts,
} from "../scripts/build-registry.mjs";

/** Build a tmp bundle dir with the given {relPath: content} files. Returns dir. */
async function makeBundle(files) {
  const dir = await mkdtemp(join(tmpdir(), "okfhub-mat-"));
  for (const [relPath, content] of Object.entries(files)) {
    const full = join(dir, relPath);
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content, "utf8");
  }
  return dir;
}

// A canonical concept body used across tests: frontmatter {type: metric} + a
// recognizable body marker. This is the raw .md the gateway serves (D-05).
const SAMPLE_BODY =
  "---\ntype: metric\ntitle: Sample Concept\n---\n\n# Sample Concept\n\nThe materialization body.\n";

test("materialize: concepts array has relPath + type + body", async () => {
  // index.md is reserved (no type) → skipped; only sample-concept.md materializes.
  const dir = await makeBundle({
    "index.md": "---\ntitle: idx\n---\n\n# Index\n",
    "sample-concept.md": SAMPLE_BODY,
  });
  try {
    const artifacts = await materializeConcepts(dir);
    assert.ok(Array.isArray(artifacts), "conceptArtifacts is an array");
    assert.equal(artifacts.length, 1, "exactly one concept (index.md is reserved)");
    const [concept] = artifacts;
    assert.equal(concept.relPath, "sample-concept.md");
    assert.equal(concept.type, "metric");
    // The body is the full markdown including the frontmatter block (the MCP
    // resource text — D-05 raw .md).
    assert.ok(typeof concept.body === "string" && concept.body.length > 0);
    assert.ok(concept.body.startsWith("---"), "body includes the frontmatter block");
    assert.match(concept.body, /Sample Concept/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("materialize: symlink concept files are rejected (T-04-SYM)", async () => {
  const dir = await makeBundle({
    "real.md": "---\ntype: table\n---\n\n# Real\n",
    "escape.md": "placeholder", // overwritten by symlink below
  });
  // Overwrite escape.md with a symlink pointing OUTSIDE the bundle dir (the
  // T-04-SYM threat: a symlink concept whose target escapes public/).
  await rm(join(dir, "escape.md"));
  await symlink(join(tmpdir(), "secret-outside-bundle.txt"), join(dir, "escape.md"));
  try {
    const artifacts = await materializeConcepts(dir);
    const relPaths = artifacts.map((a) => a.relPath).sort();
    // real.md materializes; escape.md (the symlink) is excluded, NOT followed.
    assert.deepEqual(relPaths, ["real.md"]);
    assert.ok(!relPaths.includes("escape.md"), "symlink concept was excluded");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("materialize: zero concepts (only reserved files) → empty array, no error", async () => {
  const dir = await makeBundle({
    "index.md": "# Just an index\n",
    "log.md": "# A changelog\n",
  });
  try {
    const artifacts = await materializeConcepts(dir);
    assert.ok(Array.isArray(artifacts));
    assert.equal(artifacts.length, 0, "no concept artifacts for a reserved-only bundle");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("computeEvidence: success path embeds conceptArtifacts (local clone, no network)", async () => {
  // Build a real tmp bundle, then inject a clone that resolves directly to it —
  // proves computeEvidence threads materializeConcepts output into the returned
  // bundle without a network call. The clone returns the tmp dir as bundleDir.
  const bundleDir = await makeBundle({ "sample-concept.md": SAMPLE_BODY });
  const fakeClone = async () => ({
    extractDir: bundleDir,
    bundleDir,
    resolvedRef: "deadbeef",
  });
  try {
    const manifest = {
      schema_version: 1,
      name: "materialize-fixture",
      namespace: "io.github.test",
      description: "fixture",
      version: "1.0.0",
      source: { type: "github", url: "https://github.com/test/fixture", path: "", ref: "main" },
      kind: "knowledge",
      categories: [],
    };
    const { bundle } = await computeEvidence(manifest, "io.github.test/materialize-fixture.json", {
      clone: fakeClone,
    });
    assert.ok(Array.isArray(bundle.conceptArtifacts), "bundle carries conceptArtifacts");
    assert.equal(bundle.conceptArtifacts.length, 1);
    assert.equal(bundle.conceptArtifacts[0].type, "metric");
    assert.ok(bundle.conceptArtifacts[0].body.startsWith("---"));
    // Evidence + source are still present (D-06: evidence pins the same resolved_sha).
    assert.equal(bundle.source.resolved_sha, "deadbeef");
    assert.equal(bundle.evidence.resolved_sha, "deadbeef");
  } finally {
    await rm(bundleDir, { recursive: true, force: true });
  }
});

test("computeEvidence: graceful degradation omits conceptArtifacts (no network)", async () => {
  // A malformed source URL makes the REAL cloneAndExtract throw → the catch path
  // returns the bare manifest with a warning. conceptArtifacts must be absent,
  // exactly like evidence is absent when compute fails (one bad bundle never blocks).
  const manifest = {
    schema_version: 1,
    name: "unreachable",
    namespace: "io.github.test",
    description: "fixture",
    version: "1.0.0",
    source: { type: "github", url: "not-a-github-url", path: "", ref: "main" },
    kind: "knowledge",
    categories: [],
  };
  const { bundle, warning } = await computeEvidence(
    manifest,
    "io.github.test/unreachable.json",
  );
  assert.equal(bundle.conceptArtifacts, undefined);
  assert.equal(bundle.evidence, undefined);
  assert.match(warning, /evidence compute failed/);
});
