// sanitize.test.mjs — audit M3: attacker-controlled strings interpolated into
// PR comments are neutralized before they reach postComment. Manifest fields,
// namespace paths, and changed-file names all come from a hostile PR and could
// otherwise inject Markdown formatting, links/images, or workflow-command-style
// directives via the comment body.
//
// Unit-tests sanitizeForComment directly + an end-to-end check that an injected
// namespace is rendered inert in the evaluatePullRequest failure reason.

import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluatePullRequest, sanitizeForComment } from "../../scripts/checks/gate-lib.mjs";

const REPO = "okfhub/registry";

test("sanitizeForComment: backslash-escapes Markdown-active characters", () => {
  // Every char that could format/link/spoof in a GitHub comment body is escaped.
  for (const ch of ["\\", "`", "*", "_", "[", "]", "#", "<", ">"]) {
    assert.equal(sanitizeForComment(ch), `\\${ch}`, `'${ch}' should be escaped`);
  }
});

test("sanitizeForComment: leaves plain text untouched (dots are not Markdown-active)", () => {
  assert.equal(sanitizeForComment("io.github.alice"), "io.github.alice");
  assert.equal(sanitizeForComment("plain-dash-text 123"), "plain-dash-text 123");
});

test("sanitizeForComment: collapses newlines to single spaces (defeats workflow-command lines)", () => {
  // A '::'-prefixed second line could be misread as a workflow command if it
  // ever reached an echo'd log; collapsing newlines neutralizes the vector.
  const out = sanitizeForComment("line one\n::set-output::x\r\nline three");
  assert.doesNotMatch(out, /[\r\n]/, "no newlines survive");
  assert.match(out, /line one.*set-output.*line three/);
});

test("sanitizeForComment: backtick injection is rendered literal (no code-span formatting)", () => {
  // The namespace regex restricts the namespace field to [a-z0-9-], so this
  // exact string can't appear there — but the same chars can appear in a
  // changed-file name (exercised in the e2e test below) or any free-text
  // manifest field that flows into a zod issue message.
  const malicious = "prefix`evil`suffix";
  const out = sanitizeForComment(malicious);
  assert.equal(out, "prefix\\`evil\\`suffix");
  // No raw (unescaped) backticks survive — a code span can't open.
  assert.doesNotMatch(out, /(?<!\\)`/);
});

test("end-to-end: an injected changed-file name lands in the comment escaped", async () => {
  // The "no io.github.* manifest among changed files" path interpolates the
  // changed-file list verbatim into the posted comment. A hostile PR can name
  // a file with Markdown-control chars to break formatting or smuggle a link.
  // After M3 those chars are backslash-escaped before interpolation.
  const injected = "README`](_https://evil/)`";
  const gh = async function (path, init = {}) {
    if (path.includes("/files?per_page=100")) {
      // No io.github.* file → hits the "no manifest found" branch, which
      // interpolates changedFiles into the reason.
      return new Response(
        JSON.stringify([{ filename: injected }]),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return new Response("{}", { status: 200 });
  };
  const pr = { number: 1, user: { login: "alice" }, head: { sha: "abc123" } };
  const result = await evaluatePullRequest(gh, REPO, pr);
  assert.equal(result.passed, false);
  // The injected filename MUST appear escaped — every Markdown-active char it
  // carried is now backslash-prefixed, so it can't open a code span or a link.
  assert.match(
    result.reason,
    /README\\\`\\\]\(\\_https:\/\/evil\/\)\\\`/,
    "injected filename was not escaped before interpolation",
  );
  // And the raw (unescaped) link syntax never survives — strip all escaped
  // pairs, then confirm no bare "](" link opener remains.
  assert.doesNotMatch(
    result.reason.replace(/\\./g, "").replace(/`[^`]*`/g, ""),
    /\]\(/,
    "unescaped link syntax survived",
  );
});
