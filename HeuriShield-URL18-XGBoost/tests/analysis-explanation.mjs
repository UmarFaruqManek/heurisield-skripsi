import assert from "node:assert/strict";
import { buildAnalysisExplanation } from "../src/shared/analysis-explanation.js";

const base = {
  url: "https://example.test/login",
  final_url: "https://example.test/login",
  model_result: { model_family: "XGBoost", verdict: "DANGEROUS" },
  decision_policy: { source: "url_model" },
  verdict: "DANGEROUS"
};

const unavailable = buildAnalysisExplanation(base);
assert.deepEqual(unavailable.reasons, [
  "Alamat: dinilai phishing oleh model.",
  "Identitas situs: belum dapat diperiksa.",
  "Formulir: halaman belum dapat diperiksa."
]);
assert.ok(!unavailable.reasons.join(" ").includes("domain resmi"));

const official = buildAnalysisExplanation({ ...base, verdict: "SAFE",
  model_result: { ...base.model_result, verdict: "SAFE" },
  brand_features: { claimed_brand: { name: "Example" },
    verified_reference_domain: "example.test", official_domain_match: true },
  dom_features: { observed_frame_count: 1, has_password_field: true,
    form_cross_domain: false, forms: [{ relevant: true, cross_domain: false }] } });
assert.ok(official.reasons[1].includes("domain resmi Example"));
assert.ok(official.reasons[2].includes("domain halaman ini"));

const impersonation = buildAnalysisExplanation({ ...base, verdict: "DANGEROUS",
  model_result: { ...base.model_result, verdict: "SAFE" },
  decision_policy: { source: "confirmed_credential_impersonation" },
  brand_features: { claimed_brand: { name: "Example" },
    verified_reference_domain: "example.org", official_domain_match: false },
  dom_features: { observed_frame_count: 1, has_password_field: true,
    form_cross_domain: true, forms: [{ relevant: true, cross_domain: true,
      destination_verification: false, destination_registrable_domain: "receiver.test" }] } });
assert.ok(impersonation.summary.includes("mengubah penilaian alamat menjadi phishing"));
assert.ok(impersonation.reasons[1].includes("example.org"));
assert.ok(impersonation.reasons[2].includes("receiver.test"));

const unverifiedBrand = buildAnalysisExplanation({ ...base,
  brand_features: { claimed_brand: { name: "Example" },
    official_domain_match: "unknown" } });
assert.ok(unverifiedBrand.reasons[1].includes("belum dapat diverifikasi"));
assert.ok(!unverifiedBrand.reasons[1].includes("domain resmi Example"));

const oauth = buildAnalysisExplanation({ ...base,
  dom_features: { observed_frame_count: 1, navigation: {
    observed: true, destination_type: "official_provider" }, forms: [] } });
assert.ok(oauth.reasons[2].includes("penyedia identitas resmi"));
assert.ok(oauth.reasons[2].includes("tidak membuktikan situs asal aman"));
assert.equal(oauth.title, "Terindikasi phishing");

const unknown = buildAnalysisExplanation({ ...base,
  brand_features: { claimed_brand_status: "unknown" },
  dom_features: { observed_frame_count: 1, has_password_field: true,
    form_cross_domain: false, forms: [{ relevant: true, cross_domain: false }] } });
assert.equal(unknown.reasons.length, 2);
assert.ok(!unknown.reasons.join(" ").includes("merek yang digunakan"));
const localReview = buildAnalysisExplanation({ ...base, verdict: "DANGEROUS",
  decision_policy: { source: "url_model", review_candidate: true,
    review_reason: "local_login_unverified" },
  brand_features: { claimed_brand_status: "unknown" },
  dom_features: { observed_frame_count: 1, has_password_field: true,
    form_cross_domain: false, forms: [{ relevant: true, cross_domain: false }] } });
assert.equal(localReview.title, "Terindikasi phishing");
assert.equal(localReview.reasons.length, 2);
assert.ok(localReview.limitation.includes("identitas situs belum terverifikasi"));

console.log("Explanation OK: unavailable evidence, verified domain, impersonation, OAuth");
