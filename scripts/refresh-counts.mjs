// refresh-counts.mjs — the 4×/day telemetry-only count read-back (Plan 09-03, D-03).
//
// Reads the three okfhub-counts: buckets (install / install:ci / read) from Upstash
// Redis ONCE via the REST HTTP API, merges them into a single counts.json keyed by
// `${namespace}/${name}`, and writes ./counts.json. The sibling workflow
// (refresh-counts.yml) then cross-repo-pushes counts.json → okfhub-website/public/counts.json.
//
// CRITICAL (D-03): this job writes ONLY counts.json. registry.json is UNTOUCHED — the
// heavyweight evidence/materialize/reputation build stays on its push+weekly cadence.
// Mutating registry.json 4×/day would churn the website git history and trigger full
// Vercel rebuilds; the separate counts.json isolates the churn (≤6h-stale numbers only).
//
// ZERO new npm dependencies (T-09-SC). This script uses ONLY Node's global `fetch` and
// the `node:fs` builtin — it does NOT import the Upstash Redis SDK (registry-repo's only
// declared dep is `zod`, which this script doesn't need either). Option (b) chosen over
// (a) add-the-SDK and (c) inline `node -e`: a plain fetch() to the Upstash REST HTTP API
// is dependency-free and greppable. `node --check` + an import-resolution smoke
// test in the workflow prove no undeclared module is pulled in.
//
// The Upstash REST HTTP API: GET {UPSTASH_REDIS_REST_URL}/<command>/<arg> with an
// `Authorization: Bearer <token>` header. For HGETALL the `result` is an array of
// [field1, value1, field2, value2, ...] (the raw RESP form); an absent/nonexistent key
// returns `null` or an empty array. We convert that into { "<ns>/<name>": Number(value) }
// (coercing strings → numbers; null/missing → 0).

import { writeFile } from "node:fs/promises";
import { join } from "node:path";

const REST_URL = process.env.UPSTASH_REDIS_REST_URL;
const REST_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

if (!REST_URL || !REST_TOKEN) {
  // Fail fast with a clear message. NEVER echo the token.
  console.error(
    "refresh-counts: UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN must both be set.",
  );
  process.exit(1);
}

// The three counter buckets the gateway writes (counts.ts, Plan 09-02). Each is a Redis
// HASH whose field is `${namespace}/${name}` and whose value is an integer counter.
const BUCKETS = {
  install: "okfhub-counts:install",
  install_ci: "okfhub-counts:install:ci",
  read: "okfhub-counts:read",
};

/**
 * HGETALL a single key via the Upstash REST HTTP API. Returns a
 * { "<field>": Number(value) } object (empty when the key is absent/nonexistent).
 * Never throws — one failing bucket logs + degrades to {} so a single transient Upstash
 * error does not abort the whole run.
 *
 * @param {string} key  the Redis hash key (e.g. "okfhub-counts:install")
 * @returns {Promise<Record<string, number>>}
 */
async function hgetall(key) {
  const url = `${REST_URL}/hgetall/${encodeURIComponent(key)}`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${REST_TOKEN}` },
  });
  if (!res.ok) {
    throw new Error(`Upstash ${res.status} for ${key}`);
  }
  const json = await res.json();
  const result = json?.result;
  // Absent/nonexistent key → result is null or []. Treat both as empty.
  if (!result || !Array.isArray(result) || result.length === 0) return {};
  // result is [field1, value1, field2, value2, ...] — pairs of field/value.
  const out = {};
  for (let i = 0; i < result.length; i += 2) {
    const field = result[i];
    const value = result[i + 1];
    if (typeof field === "string") {
      // Coerce the stored string integer → number; non-numeric/missing → 0.
      out[field] = Number(value) || 0;
    }
  }
  return out;
}

/**
 * Fetch all three buckets, tolerating per-bucket failure (one transient error degrades
 * that bucket to {} rather than aborting the run).
 * @returns {Promise<{install: Record<string, number>, install_ci: Record<string, number>, read: Record<string, number>}>}
 */
async function readBuckets() {
  const out = { install: {}, install_ci: {}, read: {} };
  for (const [name, key] of Object.entries(BUCKETS)) {
    try {
      out[name] = await hgetall(key);
    } catch (err) {
      // Log the bucket + the error (never the token). One bad bucket → {} for that one.
      console.error(`refresh-counts: ${name} (${key}) read failed:`, err.message);
    }
  }
  return out;
}

async function main() {
  const asOf = new Date().toISOString();
  const { install, install_ci, read } = await readBuckets();

  // Merge by `${namespace}/${name}` key across the three buckets.
  const keys = new Set([
    ...Object.keys(install),
    ...Object.keys(install_ci),
    ...Object.keys(read),
  ]);

  /** @type {Record<string, {install_count: number, install_count_ci: number, read_count: number, as_of: string}>} */
  const counts = {};
  for (const k of keys) {
    counts[k] = {
      install_count: install[k] ?? 0,
      install_count_ci: install_ci[k] ?? 0,
      read_count: read[k] ?? 0,
      as_of: asOf,
    };
  }

  // Guard: even if all three buckets were empty (no pings yet — the cron's first runs
  // before any install), still write a valid {} so data.ts's Pitfall-5 fallback has a
  // well-formed (if empty) file to read. The as_of is on each entry; an empty object is
  // the honest "no counts yet" state.
  await writeFile(join(process.cwd(), "counts.json"), `${JSON.stringify(counts, null, 2)}\n`);

  console.log(`refresh-counts: wrote counts.json with ${keys.size} bundle(s) (as_of ${asOf}).`);
}

main().catch((err) => {
  console.error("refresh-counts: failed:", err);
  process.exit(1);
});
