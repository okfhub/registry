// dns-verify.mjs — DNS TXT challenge verification (Phase 8, D-01..D-07).
//
// Verifies that a publisher of an io.http.<domain> bundle controls the zone by
// querying a per-bundle-unique DNS TXT record (_okfhub.<token8>.<domain>) against
// the AUTHORITATIVE name server directly (D-02 — bypass caching-resolver staleness,
// Pitfall 1.3). The record name is deterministic (D-03): token8 = sha8 of
// `namespace/name@sourceUrl`, so both the CLI publish command and this build-side
// re-derive the same name and no token store is needed (D-01 — no issuance server).
//
// Authoritative-NS query (D-02 — MANDATORY, empirically confirmed: Node's
// dns/promises Resolver.setServers() accepts IPs ONLY; passing a hostname throws
// ERR_INVALID_IP_ADDRESS). The 4-step sequence is fixed:
//   (1) nameservers = await resolveNs(domain)            — if empty, return false
//   (2) for each NS: nsIp = (await resolve4(ns))[0]      — on failure, try next NS
//   (3) resolver.setServers([nsIp])                      — pin to the authoritative NS
//   (4) records = await resolveTxt(recordName)           — NXDOMAIN → return false
//   join chunks per Keybase #1614 (resolveTxt returns string[][]); return true if
//   any joined value equals the expected challenge value.
//
// HTTP-03 (dated evidence, NEVER a verdict — D-07/D-08, reinforced by the May-2026
// npm Sigstore compromise): DNS proves only momentary zone-write (RFC 8555 §8.4),
// strictly weaker than durable GitHub identity. Verification renders as a dated,
// factual "DNS TXT challenge passed on <date>" — never "verified"/"safe"/"trusted".
// A verification older than 30 days (D-05) flips to the neutral dns-stale state;
// any DNS failure degrades to dns-pending, NEVER aborts a build (one bad bundle
// must never block the index — mirrors computeEvidence's per-bundle isolation).
//
// SECURITY (T-08-NS/T-08-RACE/T-08-OVERCLAIM/T-08-STALE/T-08-KEYBASE/T-08-INJECT):
//  - authoritative-NS pin defeats caching-resolver spoofing/staleness (T-08-NS).
//  - per-bundle token8 defeats the concurrent/wildcard race (T-08-RACE, D-03).
//  - staleness window + weekly re-challenge defeats domain-transfer hijack
//    (T-08-STALE, D-05, Pitfall 1.4).
//  - every detail string carries the user-controlled domain (from io.http.<domain>)
//    and is wrapped in sanitizeForComment() (T-07-INJECT); rendered as escaped
//    React text, never dangerouslySetInnerHTML.
//
// Never throws — a DNS failure degrades to dns-pending (mirrors reputation.mjs's
// computeReputation + computeEvidence's per-bundle isolation).

import { createHash } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { sanitizeForComment } from "./gate-lib.mjs";

// Bump whenever a DNS-verify logic path changes (mirrors REPUTATION_LOGIC_VERSION
// in reputation.mjs:30) so a future consumer can tell whether two DNS snapshots
// are comparable.
export const DNS_LOGIC_VERSION = 1;

// D-05 30-day staleness window. A verification older than this flips to the
// neutral dns-stale state (revoked; re-challenge pending). Matches Let's
// Encrypt's authorization-reuse period (the industry anchor for DNS-01
// revalidation); 90d would widen the domain-transfer-hijack window (Pitfall 1.4).
export const DNS_STALE_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

// D-04 poll strategy defaults: 5s initial, ×1.5 growth, 30s cap, 120s total budget.
const POLL_INITIAL_MS = 5 * 1000;
const POLL_GROWTH = 1.5;
const POLL_CAP_MS = 30 * 1000;
const POLL_BUDGET_MS = 120 * 1000;

/** The io.http.<domain> namespace prefix. */
const HTTP_NS_PREFIX = "io.http.";

/** The TXT record value prefix (D-01 — exact format Claude's discretion per
 *  CONTEXT L70; carries namespace/name so the bundle is unambiguously identified
 *  and is sanitization-safe). */
const TXT_VALUE_PREFIX = "okfhub-verify=";

/**
 * Derive the per-bundle-unique DNS TXT record name (D-03 — locked, one-way).
 *
 * `_okfhub.<token8>.<domain>` where token8 = the first 8 hex chars of sha256 of
 * `${namespace}/${name}@${sourceUrl}`. The underscore prefix follows RFC 8552
 * (scoped protocol record — zero hostname-collision risk); the per-bundle token8
 * defeats the concurrent/wildcard race (Pitfall 1.2) and is deterministic so a
 * re-challenge queries the exact same name.
 *
 * @param {string} namespace - the manifest namespace (io.http.<domain>)
 * @param {string} name - the bundle name
 * @param {string} sourceUrl - the manifest source.url (the HTTP tarball URL)
 * @param {string} domain - the domain extracted from the namespace
 * @returns {string} the TXT record name `_okfhub.<token8>.<domain>`
 */
export function challengeRecordName(namespace, name, sourceUrl, domain) {
  const token = createHash("sha256")
    .update(`${namespace}/${name}@${sourceUrl}`)
    .digest("hex")
    .slice(0, 8);
  return `_okfhub.${token}.${domain}`;
}

/** Extract the domain from an io.http.<domain> namespace. Returns the segment
 *  after `io.http.` (the domain, which may itself contain dots, e.g.
 *  io.http.example.com → example.com). Returns null for non-http namespaces. */
export function domainFromNamespace(namespace) {
  if (typeof namespace !== "string") return null;
  if (!namespace.startsWith(HTTP_NS_PREFIX)) return null;
  return namespace.slice(HTTP_NS_PREFIX.length);
}

/**
 * Query the TXT challenge against the AUTHORITATIVE name server (D-02 — the
 * MANDATORY 4-step sequence). Pinning setServers([ip]) bypasses caching-resolver
 * staleness/spoofing (T-08-NS, Pitfall 1.3); setServers accepts IPs only, so the
 * resolve4 step is mandatory infrastructure (D-02 empirically confirmed).
 *
 * Scans ALL returned TXT records, joining chunks per Keybase #1614
 * (resolveTxt returns string[][]; a single logical value may be split across
 * chunks). Returns true if any joined value equals expectedValue.
 *
 * @param {string} recordName - the _okfhub.<token8>.<domain> TXT name
 * @param {string} domain - the domain whose authoritative NS to query
 * @param {string} expectedValue - the okfhub-verify=<bundle-id> TXT value
 * @param {{resolver?: {resolveNs: Function, resolve4: Function, resolveTxt: Function, setServers: Function}}} [opts]
 *   opts.resolver is the Wave-0 mock-injection seam — tests pass a mock so NO
 *   live DNS runs in CI (08-VALIDATION.md Wave-0 deliverable). Production builds
 *   a real `new Resolver()` from node:dns/promises.
 * @returns {Promise<boolean>} true iff the authoritative NS serves the expected value
 */
export async function verifyDnsChallenge(recordName, domain, expectedValue, opts = {}) {
  const resolver = opts.resolver ?? new Resolver();

  // (1) resolveNs(domain) → the authoritative nameserver hostnames.
  let nameservers;
  try {
    nameservers = await resolver.resolveNs(domain);
  } catch {
    return false; // NXDOMAIN on the domain itself → caller polls / degrades.
  }
  if (!Array.isArray(nameservers) || nameservers.length === 0) return false;

  // (2) For each NS, resolve4(ns) → its IP. setServers needs an IP (D-02). On the
  //     first NS that resolves to an IP, proceed; if an NS fails to resolve to an
  //     IP (rare), try the next (CONTEXT Claude's Discretion: resolve4 failure path).
  let nsIp = null;
  for (const ns of nameservers) {
    try {
      const ips = await resolver.resolve4(ns);
      if (Array.isArray(ips) && ips.length > 0) {
        nsIp = ips[0];
        break;
      }
    } catch {
      // This NS won't resolve to an IP — try the next authoritative NS.
    }
  }
  if (nsIp === null) return false; // no resolvable NS IP → cannot pin → caller polls

  // (3) Pin a fresh resolver to the authoritative NS IP (bypasses the caching
  //     resolver). setServers([ip]) — IP only, per D-02.
  resolver.setServers([nsIp]);

  // (4) resolveTxt(recordName) against the pinned authoritative NS. NXDOMAIN /
  //     ENOTFOUND → false (the record is not yet published; caller polls).
  let records;
  try {
    records = await resolver.resolveTxt(recordName);
  } catch {
    return false;
  }
  if (!Array.isArray(records)) return false;

  // Scan ALL records, joining chunks per Keybase #1614 (resolveTxt returns
  // string[][]; a single logical TXT value may be split across chunks). Return
  // true if any joined value equals the expected challenge value.
  for (const chunks of records) {
    const joined = Array.isArray(chunks) ? chunks.join("") : String(chunks ?? "");
    if (joined === expectedValue) return true;
  }
  return false;
}

/**
 * Poll verifyDnsChallenge with backoff until success or budget exhaustion (D-04).
 *
 * Backoff: 5s initial, ×1.5 growth, 30s cap, 120s total budget. Returns true on
 * the first successful challenge, false when the budget is exhausted. Tests pass
 * `{ initialDelay: 0, budget: 0 }` for a single immediate shot (no waiting).
 *
 * @param {string} recordName - the _okfhub.<token8>.<domain> TXT name
 * @param {string} domain - the domain whose authoritative NS to query
 * @param {string} expectedValue - the okfhub-verify=<bundle-id> TXT value
 * @param {object} [opts] - forwarded to verifyDnsChallenge + poll overrides
 *   ({ resolver, initialDelay, growth, cap, budget }). budget <= 0 → one shot.
 * @returns {Promise<boolean>}
 */
export async function pollVerify(recordName, domain, expectedValue, opts = {}) {
  const initialDelay = opts.initialDelay ?? POLL_INITIAL_MS;
  const growth = opts.growth ?? POLL_GROWTH;
  const cap = opts.cap ?? POLL_CAP_MS;
  const budget = opts.budget ?? POLL_BUDGET_MS;

  const start = Date.now();
  let delay = initialDelay;
  // Always make at least ONE attempt immediately, regardless of budget (the
  // common case is the record is already published; tests pass budget 0 for one
  // shot). If the budget is > 0 and the first attempt fails, wait `delay` then
  // retry until the budget is exhausted.
  for (;;) {
    const ok = await verifyDnsChallenge(recordName, domain, expectedValue, opts);
    if (ok) return true;
    if (budget <= 0) return false; // single-shot mode (tests)
    if (Date.now() - start >= budget) return false;
    await sleep(Math.min(delay, cap, Math.max(0, budget - (Date.now() - start))));
    delay = Math.min(Math.round(delay * growth), cap);
  }
}

function sleep(ms) {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * The never-throw DNS verification entry point for an io.http.* bundle (mirrors
 * reputation.mjs's computeReputation shape: dispatch on source type, wrap the
 * network calls in try/catch, degrade to dns-pending on any failure).
 *
 * Computes the deterministic record name + expected value, polls the
 * authoritative NS, and returns one of three states (HTTP-03 — dated evidence,
 * never a verdict):
 *   - `dns-verified-domain` — challenge passed (or a within-window prior
 *     verification is carried forward with its ORIGINAL timestamp).
 *   - `dns-stale` — a prior verification exists but is older than 30d (D-05);
 *     rendered as "DNS verification stale; re-challenge pending".
 *   - `dns-pending` — never verified OR a transient DNS failure (no prior within
 *     the window to carry forward).
 *
 * Never throws — DNS failure degrades to dns-pending (mirrors computeEvidence's
 * per-bundle isolation: one bad bundle must never block the index).
 *
 * @param {object} manifest - validated manifest (must be source.type "http" /
 *   namespace io.http.*; non-http → dns-pending + warning)
 * @param {{dns_verified_at?: string, state?: string}} [priorBlock] - the previous
 *   build's DNS result, for the within-window carry-forward / stale detection.
 * @param {object} [opts] - { resolver (the mock seam), initialDelay, growth, cap,
 *   budget } forwarded to pollVerify.
 * @returns {Promise<{dns_verified_at?: string, state: string, token: string, warning?: string}>}
 */
export async function dnsVerify(manifest, priorBlock, opts = {}) {
  // Dispatch: only io.http.* bundles are DNS-challenged.
  const domain = domainFromNamespace(manifest?.namespace);
  if (
    !manifest?.source ||
    manifest.source.type !== "http" ||
    !domain ||
    !manifest.name
  ) {
    return {
      state: "dns-pending",
      token: undefined,
      warning: sanitizeForComment(
        `dns: source type '${manifest?.source?.type}' / namespace '${manifest?.namespace}' is not DNS-challenged (only io.http.* is verified via DNS TXT challenge).`,
      ),
    };
  }

  const recordName = challengeRecordName(
    manifest.namespace,
    manifest.name,
    manifest.source.url,
    domain,
  );
  // The expected TXT value (D-01): okfhub-verify=<namespace>/<name>. Carries the
  // bundle identity; sanitization-safe (the namespace/name are validated by the
  // schema, and the value is matched literally, not rendered raw).
  const expectedValue = `${TXT_VALUE_PREFIX}${manifest.namespace}/${manifest.name}`;

  try {
    const ok = await pollVerify(recordName, domain, expectedValue, opts);
    if (ok) {
      return {
        dns_verified_at: new Date().toISOString(),
        state: "dns-verified-domain",
        token: `${manifest.namespace}/${manifest.name}`,
      };
    }

    // Live challenge failed. Decide carry-forward vs stale vs pending from the
    // prior block's dns_verified_at (D-05 30-day window).
    return degradeFromPrior(priorBlock, domain);
  } catch (e) {
    // Never throw — degrade to pending/stale based on the prior block (mirrors
    // reputation.mjs's transientFallback + computeEvidence's catch).
    return degradeFromPrior(priorBlock, domain, errMsg(e));
  }
}

/** Decide the degraded state from the prior block (D-05 staleness window).
 *  - priorBlock within 30d → dns-verified-domain (carry-forward ORIGINAL date).
 *  - priorBlock older than 30d → dns-stale.
 *  - no priorBlock (never verified) or malformed → dns-pending.
 *  Every detail string is sanitizeForComment'd (T-07-INJECT — carries the domain). */
function degradeFromPrior(priorBlock, domain, reason) {
  const priorAt = priorBlock?.dns_verified_at;
  if (typeof priorAt === "string" && priorAt.length > 0) {
    const age = Date.now() - Date.parse(priorAt);
    if (Number.isFinite(age) && age < DNS_STALE_WINDOW_MS) {
      // Within the 30d window → carry forward the ORIGINAL dns_verified_at (the
      // rendered date shows WHEN the proof is FROM, not when the blip happened).
      return {
        dns_verified_at: priorAt,
        state: "dns-verified-domain",
        token: undefined,
      };
    }
    // Older than 30d → stale (neutral, revoked; re-challenge pending). D-05.
    return {
      state: "dns-stale",
      token: undefined,
      warning: sanitizeForComment(
        `dns: DNS verification stale for ${domain} (last passed ${priorAt}); re-challenge pending.`,
      ),
    };
  }
  // Never verified (or malformed prior) → pending.
  return {
    state: "dns-pending",
    token: undefined,
    warning: sanitizeForComment(
      `dns: verification pending for ${domain}${reason ? ` (${reason})` : ""}.`,
    ),
  };
}

function errMsg(e) {
  return e instanceof Error ? e.message : String(e);
}
