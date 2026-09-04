// reputation.mjs — publisher reputation compute (Phase 7, D-01..D-07).
//
// Computes the D-02 reputation block for a github-sourced manifest by making
// 2-3 GITHUB_TOKEN-authed GitHub REST calls (/repos, /users, [/orgs]). The
// block is attached to the bundle by build-registry.mjs::computeEvidence as a
// SIBLING to `evidence` (D-02), computed fresh on every build (D-06 —
// reputation is all-decayable, so it re-fetches every build; the cron
// carry-forward path in evidence-compute.mjs is for immutable pinned-SHA
// content checks only and is intentionally NOT reused here).
//
// D-07 distinct failure states:
//   /repos 404 → sticky `repo-unreachable` signal (persisted; NO stale stars).
//   /repos 403/429/5xx/network → transient: carry-forward last-known if <24h,
//     else pending (reputation undefined + warning).
//   /orgs 404 / user-owner → no verified-org signal (neutral, NOT negative).
//
// SECURITY (T-05/T-07-INJECT): every detail string carries the org name
// (user-controlled via source.url) and is wrapped in sanitizeForComment() at
// compute time via sanitizeSignals (mirrors sanitizeChecks). Rendered as
// escaped React text, never dangerouslySetInnerHTML.
//
// Never throws — a reputation fetch failure degrades to pending/unreachable
// (mirrors computeEvidence's per-bundle isolation).

import { makeGh, sanitizeForComment } from "./gate-lib.mjs";

// Bump whenever a signal's compute logic changes (mirrors CHECK_LOGIC_VERSION
// in evidence-compute.mjs:38) so a future consumer can tell whether two
// reputation snapshots are comparable.
export const REPUTATION_LOGIC_VERSION = 1;

// D-07 24h carry-forward window for transient failures (403/429/5xx/network).
// A transient blip carries forward the last-known block (ORIGINAL checked_at)
// only if it is within this window; otherwise reputation is pending.
export const CARRY_FORWARD_MS = 24 * 60 * 60 * 1000;

/** Parse owner/repo from a github source URL (byte-identical to
 *  build-registry.mjs:192-196 + evidence-compute.mjs:46-51). Extracts
 *  {owner, repo} for /repos, /users, and /orgs REST paths. */
function parseGithubUrl(url) {
  const m = /^https:\/\/github\.com\/([^/]+)\/([^/?#]+?)(?:\.git)?(?:[/?#]|$)/.exec(url);
  if (!m) throw new Error(`source.url '${url}' is not a recognized GitHub URL.`);
  return { owner: m[1], repo: m[2] };
}

/** Sanitize every detail string in a signals array (T-07-INJECT). Mirrors
 *  sanitizeChecks (build-registry.mjs:199-203 / evidence-compute.mjs:120-124):
 *  each detail carries the org name (user-controlled via source.url) and MUST
 *  be backslash-escaped before it is persisted into registry.json. */
function sanitizeSignals(signals) {
  return signals.map((s) =>
    s.detail !== undefined ? { ...s, detail: sanitizeForComment(s.detail) } : { ...s },
  );
}

/**
 * Compute the D-02 reputation block for a github-sourced manifest. Makes 2-3
 * GITHUB_TOKEN-authed REST calls. Returns `{ reputation }` on success, or
 * `{ reputation, warning }` for degraded states (404 sticky, transient
 * carry-forward/pending). Never throws — one bad fetch degrades to pending
 * (mirrors computeEvidence's per-bundle isolation at build-registry.mjs:182-188).
 *
 * @param {object} manifest - validated manifest (source.type dispatched below)
 * @param {object} [priorReputation] - the previous build's reputation block
 *   (for the D-07 24h carry-forward). Undefined on first compute / non-github.
 * @param {{gh?: Function}} [opts] - optional fetcher override for unit tests
 *   (mirrors computeEvidence's opts.clone override seam at L145). Production
 *   always uses makeGh(process.env.GITHUB_TOKEN).
 */
export async function computeReputation(manifest, priorReputation, opts = {}) {
  // PHASE 8 (D-07): dispatch on source.type. The http branch emits dated-factual
  // DNS signals (dns-verified-domain / dns-stale / reputation-pending) from the
  // threaded dnsVerify result — it NEVER makes a GitHub REST call and NEVER emits
  // verified-org / host-popularity (an HTTP bundle has no GitHub org; DNS never
  // reaches the GitHub-verified tier). The github branch is unchanged below.
  if (manifest?.source?.type === "http") {
    return computeHttpReputation(manifest, opts);
  }

  const { gh } = opts.gh ? { gh: opts.gh } : makeGh(process.env.GITHUB_TOKEN);

  // D-03 dispatch: only "github" is computed (today's only live source type).
  // Phase 8 adds "http" → dns-verified-domain with zero renderer rework.
  if (!manifest.source || manifest.source.type !== "github") {
    return {
      reputation: undefined,
      warning: `reputation: source type '${manifest.source?.type}' not supported (reputation skipped).`,
    };
  }

  try {
    const { owner, repo } = parseGithubUrl(manifest.source.url);

    // 1) /repos — the load-bearing popularity call (stars/forks). NEVER read
    //    the legacy `watchers` alias (it historically equals stargazers_count —
    //    use stargazers_count, the correct popularity field).
    let reposRes;
    try {
      reposRes = await gh(`/repos/${owner}/${repo}`);
    } catch (e) {
      // Network error on /repos → transient (carry-forward <24h / pending).
      return transientFallback(priorReputation, `/repos fetch failed (${errMsg(e)})`);
    }

    if (!reposRes.ok) {
      if (reposRes.status === 404) {
        // D-07 sticky repo-unreachable — PERSISTED (A-SUB), NOT omitted. The
        // repo is deleted/private, which is durable. NO stale stars carried
        // (Pitfall 2.4). The checked_at field dates the check.
        return {
          reputation: buildBlock(manifest, [
            {
              kind: "repo-unreachable",
              detail: "Source repo no longer reachable — popularity data unavailable",
            },
          ]),
        };
      }
      // 403/429 (rate-limit — primary or secondary) and 5xx → transient.
      // Use the rate-limit headers for classification detail in the warning.
      const rl = reposRes.headers.get("x-ratelimit-remaining");
      const reset = reposRes.headers.get("x-ratelimit-reset");
      const rlInfo = rl !== null ? `, x-ratelimit-remaining ${rl}` : "";
      const resetInfo = reset !== null ? `, resets ${reset}` : "";
      return transientFallback(
        priorReputation,
        `/repos transient failure (HTTP ${reposRes.status}${rlInfo}${resetInfo})`,
      );
    }

    // /repos 200 — read popularity fields (the correct ones).
    const reposJson = await reposRes.json();
    const stars = reposJson.stargazers_count;
    const forks = reposJson.forks_count;

    const signals = [
      {
        kind: "host-popularity",
        value: { stars, forks },
        detail: "popularity ≠ safety",
      },
    ];

    // 2) /users — detect org-vs-user (research A4). A User owner (e.g.
    //    io.github.asagajda → owner asagajda) emits NO verified-org signal
    //    and skips the /orgs call entirely. On any /users failure, emit NO
    //    verified-org signal (neutral — never negative, Pitfall 2.3).
    try {
      const usersRes = await gh(`/users/${owner}`);
      if (usersRes.ok) {
        const usersJson = await usersRes.json();
        if (usersJson.type === "Organization") {
          // 3) /orgs — relay GitHub's is_verified (D-01). This is GitHub's OWN
          //    org metadata (the "fourth thing"), NOT okfhub verification, NOT
          //    Phase 3 namespace auth, NOT Phase 8 DNS, NOT the pinned SHA. An
          //    /orgs 404 is NOT an error (just no verified-org signal).
          const orgsRes = await gh(`/orgs/${owner}`);
          if (orgsRes.ok) {
            const orgsJson = await orgsRes.json();
            if (orgsJson.is_verified === true) {
              signals.push({
                kind: "verified-org",
                value: true,
                detail: `Publisher ${owner} is a GitHub-verified organization.`,
              });
            }
          }
        }
        // type === "User" → no verified-org signal, no /orgs call.
      }
    } catch {
      // /users or /orgs failure → no verified-org signal (neutral). The
      // host-popularity signal (already collected) is still valid and emitted.
    }

    return { reputation: buildBlock(manifest, signals) };
  } catch (e) {
    // Never throw — degrade to pending (mirrors computeEvidence catch).
    return {
      reputation: undefined,
      warning: `reputation: compute failed (${errMsg(e)})`,
    };
  }
}

/** Build the reputation block envelope with a fresh checked_at + version fields,
 *  sanitizing every signal detail (T-07-INJECT). */
function buildBlock(manifest, signals) {
  return {
    reputation_version: 1,
    source_type: manifest.source.type,
    checked_at: new Date().toISOString(),
    reputation_logic_version: REPUTATION_LOGIC_VERSION,
    signals: sanitizeSignals(signals),
  };
}

/**
 * Compute the D-02 reputation block for an http-sourced manifest (Phase 8, D-07).
 *
 * An io.http.* bundle has NO GitHub org, so this branch NEVER emits verified-org
 * or host-popularity (DNS never reaches the GitHub-verified tier — Pitfall 1.5).
 * It reads the threaded dnsVerify result (opts.dnsResult) and emits exactly ONE
 * dated-factual signal:
 *   - dns-verified-domain → "DNS TXT challenge passed for <domain> on <date>."
 *   - dns-stale           → "DNS verification stale (last passed <priorDate>); re-challenge pending."
 *   - dns-pending         → reputation-pending "DNS verification pending."
 *
 * Every detail is dated factual copy, NEVER a verdict (D-07/D-08 — reinforced by
 * the May-2026 npm Sigstore compromise). The detail strings carry the
 * user-controlled domain (from io.http.<domain>) and are sanitizeSignals'd inside
 * buildBlock (T-07-INJECT).
 *
 * @param {object} manifest - validated http-sourced manifest
 * @param {{dnsResult?: object, priorDnsBlock?: {dns_verified_at?: string}}} opts
 *   opts.dnsResult is the dnsVerify() return threaded from computeEvidence
 *   ({ state, dns_verified_at?, token? }). opts.priorDnsBlock carries the prior
 *   build's dns_verified_at for the stale-state date. Production threads both
 *   from computeEvidence; tests inject them directly.
 * @returns {{reputation: object}} always — the http branch always emits a block
 *   (the degraded states are reputation-pending, not undefined).
 */
function computeHttpReputation(manifest, opts = {}) {
  const domain = manifest.namespace.replace(/^io\.http\./, "");
  const dnsResult = opts.dnsResult;
  const priorDnsAt = opts.priorDnsBlock?.dns_verified_at;

  let signals;
  if (dnsResult?.state === "dns-verified-domain") {
    const date = dnsResult.dns_verified_at ?? new Date().toISOString();
    signals = [
      {
        kind: "dns-verified-domain",
        value: domain,
        detail: `DNS TXT challenge passed for ${domain} on ${formatDate(date)}.`,
      },
    ];
  } else if (dnsResult?.state === "dns-stale") {
    const last = priorDnsAt ? formatDate(priorDnsAt) : "previously";
    signals = [
      {
        kind: "dns-stale",
        detail: `DNS verification stale (last passed ${last}); re-challenge pending.`,
      },
    ];
  } else {
    // dns-pending (or no dnsResult threaded — defensive default). Reuse the
    // existing pending kind (no new kind for a transient state).
    signals = [
      {
        kind: "reputation-pending",
        detail: "DNS verification pending.",
      },
    ];
  }

  return { reputation: buildBlock(manifest, signals) };
}

/** Format an ISO-8601 dns_verified_at as a YYYY-MM-DD date for dated-evidence
 *  copy (HTTP-03 — dated factual, never a verdict). Robust to malformed input. */
function formatDate(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().slice(0, 10);
}

/** D-07 transient fallback: carry-forward priorReputation (ORIGINAL checked_at)
 *  if <24h old, else reputation undefined + warning (pending). The original
 *  checked_at is preserved so the rendered date shows WHEN the data is FROM,
 *  not when the blip happened. */
function transientFallback(priorReputation, reason) {
  if (
    priorReputation &&
    typeof priorReputation.checked_at === "string" &&
    Date.now() - Date.parse(priorReputation.checked_at) < CARRY_FORWARD_MS
  ) {
    return { reputation: priorReputation };
  }
  return { reputation: undefined, warning: `reputation: transient failure (${reason}) — reputation pending.` };
}

function errMsg(e) {
  return e instanceof Error ? e.message : String(e);
}
