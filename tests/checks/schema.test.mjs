// schema.test.mjs — AUTH-03 io.github.* enforcement + missing/empty-field rejection.
// The canonical valid fixture is io.github.google/ga4-ecommerce.json (a real
// shipped manifest). Reuses the vendored ManifestSchema from schema.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkSchema } from "../../scripts/checks/schema.mjs";
import { readFile } from "node:fs/promises";

const VALID = JSON.parse(
  await readFile(new URL("../../io.github.google/ga4-ecommerce.json", import.meta.url), "utf8"),
);

test("valid manifest (real ga4-ecommerce.json fixture) → pass", () => {
  const r = checkSchema(VALID);
  assert.equal(r.passed, true, r.reason);
});

test("AUTH-03: non-io.github namespace → REJECT", () => {
  const r = checkSchema({ ...VALID, namespace: "com.example.foo" });
  assert.equal(r.passed, false);
  assert.match(r.reason, /namespace/);
});

test("AUTH-03: io.github.* with uppercase → REJECT (regex is [a-z0-9-])", () => {
  const r = checkSchema({ ...VALID, namespace: "io.github.Stripe" });
  assert.equal(r.passed, false);
});

test("AUTH-03: io.github. with empty org segment → REJECT", () => {
  const r = checkSchema({ ...VALID, namespace: "io.github." });
  assert.equal(r.passed, false);
});

test("AUTH-03: bare io.github (no org) → REJECT", () => {
  const r = checkSchema({ ...VALID, namespace: "io.github" });
  assert.equal(r.passed, false);
});

test("AUTH-03 dot-escape: '.' in the regex is LITERAL, not any-char (audit H1)", () => {
  // If the dots in /^io\.github\./ were ever unescaped, these any-char
  // stand-ins would slip through the [a-z0-9-]+ segment and validate —
  // opening the door to namespace strings the rest of the gate assumes are
  // already ruled out. Each variant swaps a '.' position for a character that
  // matches [a-z0-9-] but is NOT a literal dot.
  for (const ns of ["ioXgithubXgoogle", "io9github9google", "io-github-google"]) {
    const r = checkSchema({ ...VALID, namespace: ns });
    assert.equal(r.passed, false, `expected '${ns}' to be rejected (dots must be literal)`);
  }
  // Sanity: the legitimate form still passes.
  assert.equal(checkSchema({ ...VALID, namespace: "io.github.google" }).passed, true);
});

test("missing required field: name → REJECT", () => {
  const { name, ...noName } = VALID;
  void name;
  const r = checkSchema(noName);
  assert.equal(r.passed, false);
});

test("missing required field: version → REJECT", () => {
  const { version, ...noVer } = VALID;
  void version;
  const r = checkSchema(noVer);
  assert.equal(r.passed, false);
});

test("missing required field: description → REJECT", () => {
  const { description, ...noDesc } = VALID;
  void noDesc;
  const r = checkSchema({ ...VALID, description: undefined });
  assert.equal(r.passed, false);
});

test("empty required field: name='' → REJECT (zod min(1))", () => {
  const r = checkSchema({ ...VALID, name: "" });
  assert.equal(r.passed, false);
});

test("empty required field: namespace='' → REJECT", () => {
  const r = checkSchema({ ...VALID, namespace: "" });
  assert.equal(r.passed, false);
});

test("wrong schema_version → REJECT (literal 1)", () => {
  const r = checkSchema({ ...VALID, schema_version: 2 });
  assert.equal(r.passed, false);
});

test("missing source → REJECT", () => {
  const { source, ...noSource } = VALID;
  void source;
  const r = checkSchema(noSource);
  assert.equal(r.passed, false);
});

test("source.url not a URL → REJECT", () => {
  const r = checkSchema({ ...VALID, source: { ...VALID.source, url: "not-a-url" } });
  assert.equal(r.passed, false);
});

test("non-object input → REJECT", () => {
  assert.equal(checkSchema(null).passed, false);
  assert.equal(checkSchema("string").passed, false);
  assert.equal(checkSchema(42).passed, false);
  assert.equal(checkSchema(undefined).passed, false);
});
