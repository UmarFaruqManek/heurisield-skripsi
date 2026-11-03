import assert from "node:assert/strict";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { buildAnalysisExplanation } from "../src/shared/analysis-explanation.js";

const lookup = async token => ({ lookup_success: true, candidates: token === "youtube"
  ? [{ name: "YouTube", domain: "youtube.com", verified: true, source: "brandfetch" }] : [] });
const home = { title: "YouTube", headings: [], logos: [], controls: [], forms: [],
  password_fields: [], sensitive_fields: [], observed_at: Date.now() };
const official = await analyzeBrandEvidence(home, "https://www.youtube.com/", { lookup });
assert.deepEqual(official.searched_tokens.map(item => item.token), ["youtube"]);
assert.equal(official.brand_in_title, true);
assert.equal(official.claimed_brand?.name, "YouTube");
assert.equal(official.official_domain_match, true);
assert.equal(official.brand_domain_mismatch, false);
const genericLogin = await analyzeBrandEvidence({ ...home, title: "Sign in", headings: [] },
  "https://accounts.youtube.com/login", { lookup });
assert.equal(genericLogin.claimed_brand?.name, "YouTube");
assert.equal(genericLogin.official_domain_match, true);
const explanation = buildAnalysisExplanation({ verdict: "SAFE", hostname: "www.youtube.com",
  model_result: { model_family: "XGBoost" }, brand_features: official, correlation_rules: [],
  rdap_features: { source_domain_age_days: 1000 } });
assert.ok(explanation.reasons.some(reason => reason.includes("YouTube") && reason.includes("domain resmi")));

// A copied title on another host is not enough to claim the brand.
const unrelated = await analyzeBrandEvidence(home, "https://video.example.test/", { lookup });
assert.equal(unrelated.claimed_brand, null);
assert.equal(unrelated.official_domain_match, "unknown");
const hostOnly = await analyzeBrandEvidence(null, "https://www.youtube.com/", { lookup });
assert.equal(hostOnly.claimed_brand?.name, "YouTube");
assert.ok(hostOnly.unresolved_checks.includes("dom_unavailable"));
console.log("YouTube brand OK: title + verified own domain; copied title remains unverified");
