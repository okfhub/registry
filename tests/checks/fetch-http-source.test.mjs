// fetch-http-source.test.mjs — build-side HTTP tarball fetcher tests (Phase 8, Plan 08-02).
//
// Mirrors reputation.test.mjs's node:test + mock-injection shape. The load-bearing
// seam is opts.fetch — a mocked fetch returning a Response-like object (mirrors
// reputation.mjs's opts.gh) so NO live network runs in CI (HTTP-04, Wave-0). Covers
// the { extractDir, bundleDir, resolvedRef } contract (D-06 content SHA), redirect
// rejection (HTTP-04 Pitfall 4a — redirect:manual), non-200 handling, and the
// WR-06-hardened tar-guard (absolute-path + symlink rejection).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, writeFile, mkdir, readdir, rm, readFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fetchHttpSource } from "../../scripts/checks/fetch-http-source.mjs";

const execFileP = promisify(execFile);

/** A validated http-sourced manifest fixture. */
const MANIFEST = {
  schema_version: 1,
  name: "ga4-ecommerce",
  namespace: "io.http.example.com",
  description: "test",
  version: "1.0.0",
  source: { type: "http", url: "https://example.com/bundle.tar.gz", path: "", ref: "" },
  kind: "knowledge",
  categories: [],
};

/** Build a mock fetch that returns a Response-like object (the opts.fetch seam).
 *  Accepts either a canned tarball Buffer or a function returning one. */
function makeMockFetch(tarballBytes, { status = 200, headers = {} } = {}) {
  return async function fetch(url, init) {
    if (status >= 300 && status < 400) {
      // redirect — include the Location header so the fetcher can name it.
      return {
        ok: false,
        status,
        headers: { get: (n) => (n.toLowerCase() === "location" ? headers.location ?? "https://evil.example.com/evil.tar.gz" : null) },
        async arrayBuffer() { return new ArrayBuffer(0); },
      };
    }
    const bytes = typeof tarballBytes === "function" ? tarballBytes() : tarballBytes;
    const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: (n) => headers[n.toLowerCase()] ?? null },
      async arrayBuffer() { return ab; },
    };
  };
}

/** Build a benign OKF-bundle tarball in a tempdir (single top dir my-bundle/).
 *  Returns { bytes: Buffer, sha: string, tmp: string }. */
async function buildBenignTarball() {
  const tmp = await mkdtemp(join(tmpdir(), "okfhub-fetch-src-"));
  await mkdir(join(tmp, "my-bundle", "concepts"), { recursive: true });
  await writeFile(join(tmp, "my-bundle", "bundle.md"), "# My Bundle\n\nA test bundle.\n");
  await writeFile(join(tmp, "my-bundle", "concepts", "foo.md"), "A concept.\n");
  const out = join(tmp, "benign.tar.gz");
  await execFileP("tar", ["-czf", out, "my-bundle"], { cwd: tmp });
  const bytes = await readFile(out);
  const sha = createHash("sha256").update(bytes).digest("hex");
  return { bytes, sha, tmp };
}

/** Build a HOSTILE tarball (absolute-path entry + symlink entry) via Python's
 *  tarfile (the only reliable way to create an absolute-path + symlink tar —
 *  system tar strips leading '/' on creation). Returns { bytes, sha, tmp }.
 *  The script is written to a temp .py file (NOT passed via -c) so the b'good\n'
 *  literal is not mangled by shell/string conversion. */
async function buildEvilTarball() {
  const tmp = await mkdtemp(join(tmpdir(), "okfhub-fetch-evil-"));
  const out = join(tmp, "evil.tar.gz");
  const scriptPath = join(tmp, "build.py");
  // Write the script to a file so newlines in the source are literal Python source
  // (passing a multi-line script via `python3 -c "<string>"` mangles \n literals).
  const script = [
    "import tarfile, io",
    `with tarfile.open(${JSON.stringify(out)}, 'w:gz') as t:`,
    "    info = tarfile.TarInfo('root/good.md'); info.size = 5",
    "    t.addfile(info, io.BytesIO(b'good\\n'))",
    "    info2 = tarfile.TarInfo('/etc/passwd'); info2.size = 4",
    "    t.addfile(info2, io.BytesIO(b'evil'))",
    "    info3 = tarfile.TarInfo('root/evil-link'); info3.type = tarfile.SYMTYPE; info3.linkname = '../../etc/hostname'",
    "    t.addfile(info3)",
    "print('built')",
    "",
  ].join("\n");
  await writeFile(scriptPath, script);
  await execFileP("python3", [scriptPath]);
  const bytes = await readFile(out);
  const sha = createHash("sha256").update(bytes).digest("hex");
  return { bytes, sha, tmp };
}

test("success: a benign tarball returns { extractDir, bundleDir, resolvedRef } with resolvedRef = content SHA (D-06)", async () => {
  const { bytes, sha } = await buildBenignTarball();
  const fetch = makeMockFetch(bytes);
  const result = await fetchHttpSource(MANIFEST, { fetch });
  assert.ok(result.extractDir, "extractDir present");
  assert.ok(result.bundleDir, "bundleDir present");
  // resolvedRef MUST equal the sha256 of the downloaded tarball bytes (D-06 —
  // byte-exact; the content pin is the reproducibility anchor).
  assert.equal(result.resolvedRef, sha);
  // bundleDir points at the single top-level dir (my-bundle/).
  const entries = await readdir(result.bundleDir, { withFileTypes: true });
  assert.ok(entries.some((e) => e.name === "bundle.md"), "bundleDir contains bundle.md");
});

test("redirect (302) is NOT followed — throws naming the URL + redirect target (HTTP-04 Pitfall 4a)", async () => {
  const fetch = makeMockFetch(Buffer.alloc(0), { status: 302, headers: { location: "https://evil.example.com/evil.tar.gz" } });
  await assert.rejects(
    () => fetchHttpSource(MANIFEST, { fetch }),
    (e) => {
      assert.match(e.message, /redirect/i, "error mentions redirect");
      assert.match(e.message, /example\.com\/bundle\.tar\.gz/, "error names the source URL");
      return true;
    },
  );
});

test("redirect (301) is NOT followed either (any 3xx throws)", async () => {
  const fetch = makeMockFetch(Buffer.alloc(0), { status: 301, headers: { location: "https://moved.example.com/x.tar.gz" } });
  await assert.rejects(() => fetchHttpSource(MANIFEST, { fetch }), /redirect/i);
});

test("non-200 (e.g. 404) throws with the status", async () => {
  const fetch = makeMockFetch(Buffer.alloc(0), { status: 404 });
  await assert.rejects(
    () => fetchHttpSource(MANIFEST, { fetch }),
    (e) => /404/.test(e.message),
  );
});

test("tar-guard: a tarball with an absolute-path entry + symlink is REJECTED (WR-06-hardened isSafePath/isSafeEntry)", async () => {
  const { bytes } = await buildEvilTarball();
  const fetch = makeMockFetch(bytes);
  // The extraction must reject the unsafe entries — either by throwing during
  // list-validation (mirroring clone-source.mjs) or by refusing to extract.
  await assert.rejects(
    () => fetchHttpSource(MANIFEST, { fetch }),
    (e) => /structure|refusing|traversal|symlink|unsafe|path|extract|tar/i.test(e.message),
    "the hostile tarball is rejected by the tar-guard",
  );
});

test("success with source.path set: bundleDir = extractDir/<source.path>", async () => {
  // Build a tarball with a top dir 'my-bundle/' and a subfolder 'sub/'; set
  // source.path to 'my-bundle/sub' so bundleDir resolves there.
  const tmp = await mkdtemp(join(tmpdir(), "okfhub-fetch-path-"));
  await mkdir(join(tmp, "my-bundle", "sub"), { recursive: true });
  await writeFile(join(tmp, "my-bundle", "sub", "x.md"), "x\n");
  await writeFile(join(tmp, "my-bundle", "top.md"), "top\n");
  const out = join(tmp, "p.tar.gz");
  await execFileP("tar", ["-czf", out, "my-bundle"], { cwd: tmp });
  const bytes = await readFile(out);
  const sha = createHash("sha256").update(bytes).digest("hex");
  const fetch = makeMockFetch(bytes);
  const manifest = { ...MANIFEST, source: { ...MANIFEST.source, path: "my-bundle/sub" } };
  const result = await fetchHttpSource(manifest, { fetch });
  assert.equal(result.resolvedRef, sha);
  const entries = await readdir(result.bundleDir, { withFileTypes: true });
  assert.ok(entries.some((e) => e.name === "x.md"), "bundleDir points at the source.path subtree");
  await rm(tmp, { recursive: true, force: true });
});
