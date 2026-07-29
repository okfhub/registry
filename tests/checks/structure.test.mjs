// structure.test.mjs — the 5th merge-gate check (structural identity, D-02/D-08).
//
// Mirrors the schema.test.mjs harness (node:test + node:assert/strict). Builds
// small in-test bundle fixtures in a tmp dir so the check is exercised without
// the network clone (the workflow supplies a real STRUCTURE_BUNDLE_DIR at CI).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { checkStructure, verifyBundle } from "../../scripts/checks/structure.mjs";

const EXPECTED_IDS = ["bundle-root", "frontmatter", "type-present", "min-concepts", "links-resolve"];

/** Build a tmp bundle dir with the given concept files. Returns the dir path. */
async function makeBundle(files) {
  const dir = await mkdtemp(join(tmpdir(), "okfhub-struct-"));
  for (const [relPath, content] of Object.entries(files)) {
    const full = join(dir, relPath);
    await mkdir(join(full, ".."), { recursive: true });
    await writeFile(full, content, "utf8");
  }
  return dir;
}

test("valid bundle (concept with type frontmatter) → checkStructure passes", async () => {
  const dir = await makeBundle({
    "concepts/orders.md": "---\ntype: BigQuery Table\n---\n\n# Orders\n",
  });
  try {
    const r = await checkStructure({ bundleDir: dir });
    assert.equal(r.passed, true, r.reason);
    assert.match(r.reason, /structure: bundle passes identity checks/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("missing-type concept → checkStructure fails, reason names 'type' check", async () => {
  const dir = await makeBundle({
    "concepts/bad.md": "---\ntitle: no type here\n---\n\n# Bad\n",
  });
  try {
    const r = await checkStructure({ bundleDir: dir });
    assert.equal(r.passed, false);
    assert.match(r.reason, /^structure: type/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("no frontmatter concept → checkStructure fails naming frontmatter check", async () => {
  const dir = await makeBundle({
    "concepts/bare.md": "# Bare concept with no frontmatter at all\n",
  });
  try {
    const r = await checkStructure({ bundleDir: dir });
    assert.equal(r.passed, false);
    // The check name is "Frontmatter parses" (capital F) — match case-insensitively.
    assert.match(r.reason, /structure: Frontmatter parses/i);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("empty bundle (only index.md) → fails min-concepts", async () => {
  const dir = await makeBundle({
    "index.md": "# Just an index, no concepts\n",
  });
  try {
    const r = await checkStructure({ bundleDir: dir });
    assert.equal(r.passed, false);
    assert.match(r.reason, /structure: (≥1 concept|min-concepts)/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("quality warning (dangling link) never blocks — D-09", async () => {
  const dir = await makeBundle({
    "concepts/sales.md":
      "---\ntype: Dataset\n---\n\n# Sales\n\n[missing](datasets/overview.md)\n",
  });
  try {
    const r = await checkStructure({ bundleDir: dir });
    // Identity passes (valid frontmatter + type + ≥1 concept); links-resolve
    // warns but D-09 makes quality advisory — the gate must still pass.
    assert.equal(r.passed, true, r.reason);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("verifyBundle returns the D-10 EvidenceCheck array (5 checks, correct ids)", async () => {
  const dir = await makeBundle({
    "concepts/orders.md": "---\ntype: Table\n---\n\n# Orders\n",
  });
  try {
    const { checks } = await verifyBundle(dir);
    assert.equal(checks.length, 5);
    assert.deepEqual(
      checks.map((c) => c.id),
      EXPECTED_IDS,
    );
    for (const c of checks) {
      assert.ok(["identity", "quality"].includes(c.severity), `bad severity on ${c.id}`);
      assert.ok(["pass", "warn", "fail", "skipped"].includes(c.status), `bad status on ${c.id}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("path-traversal link target is rejected, not followed (T-04-PATH)", async () => {
  const dir = await makeBundle({
    "concepts/sneaky.md":
      "---\ntype: Table\n---\n\n# Sneaky\n\n[escape](../../../../etc/passwd)\n",
  });
  try {
    const { checks } = await verifyBundle(dir);
    const links = checks.find((c) => c.id === "links-resolve");
    // The traversal target counts as dangling (rejected) — never reads outside.
    assert.equal(links.status, "warn");
    assert.match(links.detail, /etc\/passwd/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
