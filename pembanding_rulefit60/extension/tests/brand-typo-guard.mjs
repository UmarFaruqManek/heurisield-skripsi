import assert from "node:assert/strict";
import { applyBrandClaimGuard } from "../src/shared/brand-claim-guard.js";

const model = { ready: true, verdict: "SAFE", predicted_label: "legitimate", probability_phishing: 0.41 };
const options = {
  originalUrl: "https://www.robiox.com.gr/users/4890711579/profile",
  finalUrl: "https://www.robiox.com.gr/users/4890711579/profile",
  title: "Roblox | Profile",
  domFeatures: { credential_form_count: 0 },
  brandFeatures: {
    brand_top_candidate_domain: "robiox.com.gr",
    brand_top_candidate_name: "Roblox",
    brand_top_candidate_source: "brandfetch",
    brand_quality_score: 0.486
  },
  lookup: async (query) => query === "roblox"
    ? { lookup_success: true, candidates: [{ domain: "roblox.com", name: "Roblox", qualityScore: 0.96 }] }
    : { lookup_success: true, candidates: [] }
};

const flagged = await applyBrandClaimGuard(model, options);
assert.equal(flagged.verdict, "DANGEROUS");
assert.equal(flagged.post_model_guard.id, "CORROBORATED_BRAND_TYPO");
assert.equal(flagged.raw_probability_phishing, 0.41);

for (const variant of [
  { title: "Unrelated website" },
  { brandFeatures: { ...options.brandFeatures, brand_quality_score: 0.7 } },
  { lookup: async () => ({ lookup_success: true, candidates: [{ domain: "roblox.com", name: "Roblox", qualityScore: 0.4 }] }) }
]) {
  const unchanged = await applyBrandClaimGuard(model, { ...options, ...variant });
  assert.equal(unchanged.verdict, "SAFE");
}
console.log("Brand typo guard checks passed");
