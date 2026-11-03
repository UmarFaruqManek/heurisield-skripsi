import { searchClearbit, searchBrandfetch } from "./brand-features.js";
import { lookupBrandByDomain } from "./brand-domain-api.js";

// Exact domain match only; never select the first fuzzy directory suggestion.
export async function searchDomainBrand(domain, {
  clearbit = searchClearbit, brandfetch = searchBrandfetch,
  domainLookup = lookupBrandByDomain
} = {}) {
  const query = String(domain || "").trim().toLowerCase().replace(/\.$/, "");
  const attempts = [];
  for (const [provider, lookup] of [["clearbit", clearbit], ["brandfetch", brandfetch]]) {
    let result;
    try { result = await lookup(query); }
    catch { result = { lookup_success: false, status: "network_error", candidates: [] }; }
    const exact = (result.candidates || []).filter(candidate =>
      String(candidate.domain || "").toLowerCase().replace(/\.$/, "") === query && candidate.name);
    attempts.push({ provider, lookup_success: result.lookup_success === true,
      status: result.status || (result.lookup_success ? "completed" : "failed"),
      http_status: result.http_status ?? null, retry_after_ms: result.retry_after_ms ?? null,
      candidate_count: exact.length });
    if (result.lookup_success === true && exact.length) return {
      query, queried_domain: query, found: true, lookup_success: true,
      candidates: exact, provider_attempts: attempts, status: "matched" };
  }
  let directory;
  try { directory = await domainLookup(query); }
  catch { directory = { lookup_success: false, found: false, error: "network_error" }; }
  const exact = directory.lookup_success === true && directory.found === true &&
    String(directory.registrable_domain || directory.domain || "").toLowerCase() === query && directory.brand_name;
  attempts.push({ provider: "heurishield_domain", lookup_success: directory.lookup_success === true,
    status: directory.error || (exact ? "matched" : "no_match"), candidate_count: exact ? 1 : 0 });
  return { query, queried_domain: query, found: Boolean(exact),
    lookup_success: attempts.some(attempt => attempt.lookup_success),
    status: exact ? "matched" : attempts.every(a => a.lookup_success) ? "no_match" : "incomplete",
    provider_attempts: attempts, domain_response: directory,
    candidates: exact ? [{ name: directory.brand_name, domain: query,
      verified: directory.brand_verified === true, source: "existing_brand_domain_api" }] : [] };
}
