import { registrable } from "../dom/dom-evidence.js";
import { TRUSTED_OAUTH_PROVIDER_DOMAINS } from "../../utils/constants.js";
import { parse as parseDomain } from "../../shared/tldts.js";

const UNKNOWN = "unknown";
const norm = x => String(x || "").normalize("NFKC").toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ").trim();
const safeTokens = text => norm(text).split(" ").filter(x => x.length >= 3 && !/^(?:login|sign|with|continue|masuk|dengan|account|verify|verification|tutorial|guide|cara|halaman|page|home|website|official|resmi)$/.test(x));
const HOST_GENERIC = new Set(["www", "app", "apps", "api", "login", "signin", "auth", "account", "accounts", "secure", "verify", "support", "admin", "sso", "mfa", "mail", "com", "net", "org", "co", "ac", "id", "gov", "edu"]);
export function brandHostQueries(url) {
  let hostname;
  try { hostname = new URL(url).hostname.toLowerCase().replace(/\.$/, ""); } catch { return []; }
  const parts = parseDomain(hostname, { allowPrivateDomains: true });
  if (parts.isIp || !parts.domainWithoutSuffix) return [];
  const labels = [...(parts.subdomain || "").split(".").filter(Boolean), parts.domainWithoutSuffix];
  const queries = [];
  for (const label of labels) {
    for (const token of safeTokens(label)) {
      if (!HOST_GENERIC.has(token) && !/^\d+$/.test(token) && !queries.includes(token)) queries.push(token);
    }
  }
  return queries.slice(0, 5);
}
const hasBrand = (text, name) => new RegExp(`(?:^|\\s)${norm(name).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:$|\\s)`, "u").test(norm(text));
function oneEditApart(a, b) {
  if (a.length < 5 || b.length < 5 || Math.abs(a.length - b.length) > 1) return false;
  let i = 0, j = 0, edits = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) { i++; j++; continue; }
    if (++edits > 1) return false;
    if (a.length > b.length) i++;
    else if (b.length > a.length) j++;
    else { i++; j++; }
  }
  return edits + (a.length - i) + (b.length - j) === 1;
}
function providerDomain(name) {
  const token = norm(name).replace(/ /g, "");
  return [...TRUSTED_OAUTH_PROVIDER_DOMAINS].find(d => norm(d.split(".")[0]) === token) || null;
}
function domainMatch(page, official) {
  try {
    const host = new URL(page).hostname.toLowerCase().replace(/\.$/, "");
    const root = String(official || "").toLowerCase();
    if (!root || !registrable(`https://${root}`)) return false;
    // Shared hosting tenants are not made official by a suffix match.
    return host === root || (registrable(page) === root && host.endsWith(`.${root}`));
  } catch { return false; }
}

function hostBrandClaim(url, candidate) {
  try {
    const host = new URL(url).hostname.toLowerCase();
    const parsed = parseDomain(host, { allowPrivateDomains: true });
    const label = norm(parsed.domainWithoutSuffix).replace(/\s/g, "");
    const reference = norm(candidate.domain?.split(".")[0]).replace(/\s/g, "");
    if (!label || !reference) return null;
    if (label === reference) return "exact";
    if (oneEditApart(label, reference)) return "lookalike";
    // Searchable subdomain tokens were already parsed with the public/private
    // suffix list. Reuse them as host evidence, excluding generic labels.
    const subdomainTokens = (parsed.subdomain || "").split(".")
      .flatMap(safeTokens).filter(token => !HOST_GENERIC.has(token) && !/^\d+$/.test(token));
    if (subdomainTokens.includes(reference)) return "subdomain_exact";
    return subdomainTokens.some(token => oneEditApart(token, reference))
      ? "subdomain_lookalike" : null;
  } catch { return null; }
}

export async function analyzeBrandEvidence(snapshot, url, { lookup, domainLookup, verifyLookup } = {}) {
  const domUnavailable = !snapshot;
  // Even without a readable page, hostname tokens can yield an explicitly
  // unverified candidate. They cannot establish a page claim or trigger a rule.
  if (!snapshot) snapshot = { title: "", headings: [], logos: [], controls: [],
    password_fields: [], forms: [], sensitive_fields: [] };
  const title = String(snapshot.title || "");
  const headings = (snapshot.headings || []).map(h => h.text || "");
  const logos = (snapshot.logos || []).filter(l => l.context === "primary").map(l => l.text || "");
  const providers = (snapshot.controls || []).filter(c => c.type === "oauth_login").map(c => c.provider).filter(Boolean);
  const providerNorms = new Set(providers.map(norm));
  const queryText = [title, ...headings.slice(0, 3), ...logos.slice(0, 2)];
  // Host labels provide search candidates; they do not establish a page claim.
  const hostQueries = brandHostQueries(url);
  let fallbackDomainResult = null;
  const queries = [...new Set([...hostQueries, ...queryText.flatMap(safeTokens)])].slice(0, 8);
  const results = await Promise.all(queries.map(async token => {
    try { return await lookup(token); } catch { return { lookup_success: false, candidates: [] }; }
  }));
  let candidates = results.flatMap((r, i) => (r?.candidates || []).map(c => {
    const name = norm(c.name), label = norm(c.domain?.split(".")[0]);
    const approximate = oneEditApart(queries[i], label);
    const rank = name === queries[i] || label === queries[i] ? 3 : approximate ? 2 :
      queries[i].length >= 4 && name.split(" ").includes(queries[i]) ? 1 : 0;
    return { ...c, token: queries[i], approximate, rank };
  }).filter(c => c.rank > 0).sort((a, b) => b.rank - a.rank).slice(0, 2));
  // Existing provider registry supplies exact official-domain evidence for supported IdPs.
  for (const token of queries) {
    const domain = providerDomain(token);
    if (domain && !candidates.some(c => norm(c.name) === token && c.domain === domain)) candidates.push({ name: token, domain, verified: true, source: "existing_oauth_provider_domains", token });
  }
  // A generic token may return many unrelated brands. The domain directory is
  // still needed when none of those results identifies the visited domain.
  if (!candidates.some(c => domainMatch(url, c.domain)) && domainLookup) {
    const root = registrable(url);
    if (root) {
      try {
        const found = await domainLookup(root);
        fallbackDomainResult = found;
        if (found?.lookup_success && found?.found && found.brand_name) {
          candidates.push({ name: found.brand_name, domain: root, verified: found.brand_verified === true,
            source: "existing_brand_domain_api", token: norm(found.brand_name) });
        }
      } catch {}
    }
  }
  candidates = candidates.filter(c => c.name && c.domain).slice(0, 16);
  // A directory result can match the visited domain without proving ownership.
  // Keep this observable match separate from B05 (verified official domain).
  const matchingDomainCandidates = candidates.filter(c => domainMatch(url, c.domain));
  const matchedDomainCandidate = matchingDomainCandidates.find(c => c.verified === true) ||
    matchingDomainCandidates[0] || null;
  const scored = candidates.map(c => {
    const inTitle = hasBrand(title, c.name);
    const inHeading = headings.some(h => hasBrand(h, c.name));
    const inLogo = logos.some(l => hasBrand(l, c.name));
    const oauthOnly = providerNorms.has(norm(c.name)) && !inTitle && !inHeading && !inLogo;
    const providerOnlyContext = providerNorms.has(norm(c.name)) && !inLogo &&
      /(?:sign in|log in|login|masuk|continue)\s+(?:with|using|dengan|via)\s+/i.test(`${title} ${headings.join(" ")}`) &&
      !(snapshot.password_fields || []).length;
    const article = /(?:tutorial|panduan|cara|guide|artikel|news|berita|review)\b/i.test(`${title} ${headings[0] || ""}`);
    // A verified exact official domain identifies its own brand even on a
    // login page with a generic title. A copied title elsewhere does not.
    const hostClaim = hostBrandClaim(url, c);
    const verifiedOwnDomain = c.verified === true && domainMatch(url, c.domain);
    const claim = Boolean(!oauthOnly && !providerOnlyContext &&
      (verifiedOwnDomain || (!article && ((inTitle && inHeading) ||
        (inLogo && (inTitle || inHeading)) || (inTitle && hostClaim)))));
    return { ...c, inTitle, inHeading, inLogo, hostClaim, claim, oauthOnly, article };
  });
  const claims = scored.filter(c => c.claim);
  const claimNames = [...new Set(claims.map(c => norm(c.name)))];
  // A supported claim on the actual registrable domain outranks broad words
  // in the same page (e.g. Merdeka/Siber versus Merdeka Siber). A copied brand
  // on another domain cannot gain this preference.
  const ownClaims = claims.filter(c => domainMatch(url, c.domain));
  const strongExternalClaims = claims.filter(c => !domainMatch(url, c.domain) &&
    c.verified === true && c.inTitle && (c.inHeading || c.inLogo) &&
    (snapshot.password_fields || []).length > 0);
  const ownPageClaim = ownClaims.some(c => c.inTitle || c.inHeading || c.inLogo);
  const domainLabel = norm(parseDomain(new URL(url).hostname,
    { allowPrivateDomains: true }).domainWithoutSuffix).replace(/\s/g, "");
  const chosen = strongExternalClaims.length === 1 && !ownPageClaim
    ? strongExternalClaims[0]
    : ownClaims.length
    ? [...ownClaims].sort((a, b) =>
      Number(norm(b.name).replace(/\s/g, "") === domainLabel) -
      Number(norm(a.name).replace(/\s/g, "") === domainLabel) ||
      Number(b.verified) - Number(a.verified) ||
      Number(b.inTitle) + Number(b.inHeading) + Number(b.inLogo) -
      Number(a.inTitle) - Number(a.inHeading) - Number(a.inLogo))[0]
    : claimNames.length === 1
      ? claims.filter(c => norm(c.name) === claimNames[0])
        .sort((a, b) => Number(b.verified) - Number(a.verified))[0]
      : null;
  let official = UNKNOWN, officialDomain = null;
  let verified = false;
  let verificationResult = null;
  let domainResult = null;
  if (chosen) {
    // A search result alone is a candidate. Brandfetch verified or the existing IdP
    // registry may establish the official domain; the domain API can corroborate it.
    verified = chosen.verified === true;
    // The first parallel lookup can return Clearbit while Brandfetch times out.
    // Retry only the single claimed brand; never treat an API candidate alone as verified.
    const verificationHostClaim = hostBrandClaim(url, chosen);
    const verificationNeedsPageEvidence = verificationHostClaim?.startsWith("subdomain_")
      ? (snapshot.password_fields || []).length > 0 && (chosen.inHeading || chosen.inLogo)
      : Boolean(verificationHostClaim);
    if (!verified && verifyLookup && chosen.inTitle &&
        (verificationNeedsPageEvidence || (snapshot.password_fields || []).length)) {
      try {
        const response = await verifyLookup(chosen.name);
        verificationResult = response;
        verified = response?.lookup_success === true && (response.candidates || []).some(c =>
          c.verified === true && c.domain === chosen.domain && norm(c.name) === norm(chosen.name));
      } catch {}
    }
    let verifiedPageDomain = null;
    const root = registrable(url);
    if (domainLookup && root) {
      try {
        const response = fallbackDomainResult || await domainLookup(root);
        domainResult = response;
        if (response?.lookup_success && response?.found && response?.brand_verified === true && norm(response.brand_name) === norm(chosen.name)) {
          verified = true;
          verifiedPageDomain = root;
        }
      } catch {}
    }
    if (verified) {
      officialDomain = verifiedPageDomain || chosen.domain;
      official = domainMatch(url, officialDomain);
    }
  }
  // A different verified reference domain is a potential mismatch. It cannot
  // prove impersonation on its own, since partner domains may legitimately exist.
  const mismatch = official === true ? false : UNKNOWN;
  const hostClaim = chosen ? hostBrandClaim(url, chosen) : null;
  const subdomainClaim = hostClaim === "subdomain_exact" || hostClaim === "subdomain_lookalike";
  const highConfidenceHostImpersonation = Boolean(chosen && verified && official === false &&
    hostClaim && chosen.inTitle && !chosen.article && !chosen.oauthOnly &&
    (!subdomainClaim || ((snapshot.password_fields || []).length > 0 &&
      (chosen.inHeading || chosen.inLogo))));
  const highConfidenceCredentialImpersonation = Boolean(chosen && verified && official === false &&
    (snapshot.password_fields || []).length &&
    (chosen.inTitle && chosen.inHeading || chosen.inLogo && chosen.inTitle));
  return {
    observed_at: snapshot.observed_at || null,
    searched_tokens: queries.map(token => ({ token, source: hostQueries.includes(token) ? "hostname" : "page", lookup_success: results[queries.indexOf(token)]?.lookup_success === true })),
    brand_in_title: !title ? UNKNOWN : candidates.length ? scored.some(c => c.inTitle) : results.some(r => r?.lookup_success) ? false : UNKNOWN,
    brand_in_heading: !headings.length ? UNKNOWN : candidates.length ? scored.some(c => c.inHeading) : results.some(r => r?.lookup_success) ? false : UNKNOWN,
    brand_in_logo: snapshot.logos?.length ? scored.some(c => c.inLogo) ? true : logos.length && results.some(r => r?.lookup_success) ? false : UNKNOWN : false,
    claimed_brand: chosen ? { id: chosen.brandId || chosen.domain, name: chosen.name, official_domain: officialDomain } : null,
    claimed_brand_status: chosen ? "identified" : claimNames.length > 1 ? "ambiguous" : "unknown",
    candidate_domain_match: matchingDomainCandidates.length > 0,
    domain_matched_candidate: matchedDomainCandidate ? {
      name: matchedDomainCandidate.name, domain: matchedDomainCandidate.domain,
      source: matchedDomainCandidate.source || null,
      verified: matchedDomainCandidate.verified === true
    } : null,
    brand_claim_relation: chosen ? domainMatch(url, chosen.domain) ? "own_domain" : "external_domain" : UNKNOWN,
    verified_reference_domain: officialDomain,
    host_brand_claim: hostClaim || UNKNOWN,
    high_confidence_host_impersonation: highConfidenceHostImpersonation,
    high_confidence_credential_impersonation: highConfidenceCredentialImpersonation,
    lookup_replay: {
      searches: queries.map((token, index) => ({ token, lookup_success: results[index]?.lookup_success === true,
        provider_attempts: results[index]?.provider_attempts || [],
        candidates: (results[index]?.candidates || []).map(c => ({ name: c.name, domain: c.domain,
          verified: c.verified === true, source: c.source, score_source: c.score_source || null,
          brandId: c.brandId || null })) })),
      verification: verificationResult ? { token: chosen?.name, lookup_success: verificationResult.lookup_success === true,
        candidates: (verificationResult.candidates || []).map(c => ({ name: c.name, domain: c.domain,
          verified: c.verified === true, source: c.source })) } : null,
      domain: (domainResult || fallbackDomainResult) ? {
        lookup_success: (domainResult || fallbackDomainResult).lookup_success === true,
        found: (domainResult || fallbackDomainResult).found === true,
        brand_name: (domainResult || fallbackDomainResult).brand_name || null,
        brand_verified: (domainResult || fallbackDomainResult).brand_verified === true,
        registrable_domain: (domainResult || fallbackDomainResult).registrable_domain || null
      } : null
    },
    official_domain_match: official,
    brand_domain_mismatch: mismatch, potential_mismatch: official === false,
    mentioned_brands: scored.filter(c => !c.claim && (c.inTitle || c.inHeading || c.inLogo || providerNorms.has(norm(c.name)))).map(c => c.name),
    hostname_brand_candidates: scored.filter(c => hostQueries.includes(c.token)).map(c => ({ name: c.name, candidate_domain: c.domain, token: c.token, approximate: c.approximate === true })),
    oauth_providers: providers, candidates: scored.map(c => ({ name: c.name, domain: c.domain, source: c.source, verified: c.verified === true, approximate: c.approximate === true, in_title: c.inTitle, in_heading: c.inHeading, in_logo: c.inLogo, claim: c.claim })),
    unresolved_checks: [domUnavailable ? "dom_unavailable" : null,
      official === UNKNOWN && chosen ? "official_domain_unverified" : null].filter(Boolean)
  };
}
