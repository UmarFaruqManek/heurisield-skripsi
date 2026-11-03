import assert from "node:assert/strict";
import { searchBrand } from "../src/analyzer/brand/brand-features.js";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { buildAnalysisExplanation } from "../src/shared/analysis-explanation.js";
import { decideWithEvidence } from "../src/analyzer/correlation/decision-policy.js";
import { analyzeDomEvidence } from "../src/analyzer/dom/dom-evidence.js";
import { evaluateCorrelation } from "../src/analyzer/correlation/evidence-rules.js";
import { extractUrl18Features } from "../src/analyzer/url/url18-features.js";
import { predictProbability } from "../src/model/xgboost-engine.js";
import { readFileSync } from "node:fs";

const calls = [];
const originalFetch = globalThis.fetch;
globalThis.fetch = async url => {
  calls.push(String(url));
  return String(url).includes("clearbit")
    ? { ok: false, status: 503 }
    : { ok: true, json: async () => [{ name: "isMalicious", domain: "ismalicious.com", verified: false }] };
};
try {
  const result = await searchBrand("ismalicious", {
    clearbit: { apiUrl: "https://clearbit.test/search?query={token}" },
    brandfetch: { apiUrl: "https://brandfetch.test/search/{query}" }
  });
  assert.equal(result.candidates[0].name, "isMalicious");
  assert.equal(result.provider_attempts[0].lookup_success, false);
  assert.equal(result.provider_attempts[1].candidate_count, 1);
  assert.match(calls[0], /clearbit/);
  assert.match(calls[1], /brandfetch/);
} finally { globalThis.fetch = originalFetch; }

const snapshot = (title, heading, logo = "", password = false) => ({ title,
  headings: [{ text: heading }], logos: logo ? [{ text: logo, context: "primary" }] : [],
  controls: [], forms: [], password_fields: password ? [{ form_index: 0 }] : [],
  sensitive_fields: [] });
const lookup = async token => ({ lookup_success: true, candidates: ({
  portal: [{ name: "Portal", domain: "portal.app" }],
  merdekasiber: [{ name: "Merdeka Siber", domain: "merdekasiber.com" }],
  merdeka: [{ name: "Merdeka", domain: "merdeka.com.hk" }],
  siber: [{ name: "Siber", domain: "siber.com" }],
  ismalicious: [{ name: "isMalicious", domain: "ismalicious.com" }],
  database: [{ name: "DataBase", domain: "database.com.tr" }],
  google: [{ name: "Google", domain: "google.com", verified: true }],
  example: [{ name: "Example", domain: "example.test", verified: true }]
})[token] || [] });

const merdeka = await analyzeBrandEvidence(
  snapshot("Merdeka Siber Private Labs", "Merdeka Siber Labs", "Merdeka Siber"),
  "https://portal.merdekasiber.com/", { lookup });
assert.equal(merdeka.claimed_brand?.name, "Merdeka Siber");
assert.equal(merdeka.brand_claim_relation, "own_domain");
assert.equal(merdeka.claimed_brand_status, "identified");
const portalUrl = "https://portal.merdekasiber.com/";
const portalModel = JSON.parse(readFileSync(new URL("../src/model/xgboost-url18.json", import.meta.url)));
const portalScore = predictProbability(portalModel,
  { ...extractUrl18Features(portalUrl), domain_age_days: 1752 });
const portalDom = analyzeDomEvidence([{ page_origin: "https://portal.merdekasiber.com",
  forms: [{ relevant: true, action_known: true, action_origin: "https://portal.merdekasiber.com" }],
  password_fields: [{ form_index: 0 }], sensitive_fields: [], controls: [] }]);
assert.ok(portalScore > portalModel.threshold && portalScore < 0.60);
assert.equal(decideWithEvidence("DANGEROUS", portalDom, merdeka,
  evaluateCorrelation(portalDom, merdeka),
  { probability: portalScore, domainAgeDays: 1752, sameSite: true,
    parentSiteLink: true, pageRegistrableDomain: "merdekasiber.com" }).verdict, "SAFE");
const merdekaExplanation = buildAnalysisExplanation({ verdict: "SAFE",
  model_result: { model_family: "XGBoost" }, brand_features: merdeka,
  rdap_features: { source_domain_age_days: 900 }, correlation_rules: [] });
assert.ok(merdekaExplanation.reasons.some(reason => reason.includes("Merdeka Siber") &&
  reason.includes("belum dapat diverifikasi")));
const correctedExplanation = buildAnalysisExplanation({ verdict: "SAFE",
  url: "https://portal.merdekasiber.com/", final_url: "https://portal.merdekasiber.com/",
  model_result: { model_family: "XGBoost", verdict: "DANGEROUS", probability_phishing: 0.5809 },
  decision_policy: { source: "corroborated_own_domain_review", corroboration: "parent_site_link" }, brand_features: merdeka,
  dom_features: portalDom, rdap_features: { source_domain_age_days: 1752 }, correlation_rules: [] });
assert.equal(correctedExplanation.domain, "portal.merdekasiber.com");
assert.ok(correctedExplanation.reasons.some(reason => reason.includes("Merdeka Siber")));
assert.ok(correctedExplanation.summary.includes("mengubah penilaian alamat menjadi legitimate"));
assert.ok(correctedExplanation.reasons.some(reason => reason.includes("domain halaman ini")));
assert.ok(!correctedExplanation.reasons.some(reason => reason.includes("Umur domain")));

const ismalicious = await analyzeBrandEvidence(
  snapshot("Phishing URLs - Active Phishing Site Database | isMalicious",
    "Phishing URLs Active phishing database"),
  "https://ismalicious.com/data/phishing-urls", { lookup });
assert.equal(ismalicious.claimed_brand?.name, "isMalicious");
assert.equal(ismalicious.claimed_brand_status, "identified");

let domainCalls = 0;
const domainFallback = await analyzeBrandEvidence(snapshot("Example", "Welcome"),
  "https://example.test/", {
    lookup: async () => ({ lookup_success: true, candidates: [{ name: "Unrelated", domain: "other.test" }] }),
    domainLookup: async root => { domainCalls++; return { lookup_success: true, found: true,
      registrable_domain: root, brand_name: "Example", brand_verified: false }; }
  });
assert.equal(domainCalls, 1); // Reuse the fallback response for corroboration.
assert.equal(domainFallback.claimed_brand?.name, "Example");
assert.equal(domainFallback.official_domain_match, "unknown");

const fakeGoogle = await analyzeBrandEvidence(snapshot("Google Login", "Sign in to Google", "", true),
  "https://google-login.example.test/", { lookup });
assert.equal(fakeGoogle.claimed_brand?.name, "Google");
assert.equal(fakeGoogle.high_confidence_credential_impersonation, true);
assert.equal(fakeGoogle.brand_claim_relation, "external_domain");
console.log("Brand API chain OK: fallback, domain preference, page ambiguity, impersonation");
