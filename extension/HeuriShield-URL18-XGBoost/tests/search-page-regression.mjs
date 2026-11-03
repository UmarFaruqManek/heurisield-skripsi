import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { extractUrl18Features } from "../src/analyzer/url/url18-features.js";
import { predictProbability } from "../src/model/xgboost-engine.js";
import { analyzeDomEvidence } from "../src/analyzer/dom/dom-evidence.js";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { evaluateCorrelation } from "../src/analyzer/correlation/evidence-rules.js";
import { decideWithEvidence } from "../src/analyzer/correlation/decision-policy.js";
import { buildAnalysisExplanation } from "../src/shared/analysis-explanation.js";

const model = JSON.parse(readFileSync(new URL("../src/model/xgboost-url18.json", import.meta.url)));
const url = "https://www.google.com/search?q=bca&oq=bca&gs_lcrp=EgZjaHJvbWUqBwgAEAAYjwIyBwgAEAAYjwIyFggBEC4YgwEYxwEYsQMYyQMY0QMYgAQyDQgCEAAYgwEYsQMYgAQyDQgDEAAYgwEYsQMYgAQyDQgEEAAYkgMYgAQYigUyDQgFEAAYkgMYgAQYigUyCggGEAAYsQMYgAQyDQgHEAAYgwEYsQMYgAQyCggIEAAYsQMYgAQyCggJEAAYsQMYgATSAQc0NjRqMGo3qAIAsAIA&sourceid=chrome&source=chrome.ob&ie=UTF-8";
const probability = predictProbability(model, { ...extractUrl18Features(url), domain_age_days: 10658 });
assert.ok(probability >= model.threshold && probability < 0.6);
const snapshot = { page_origin: "https://www.google.com", title: "bca - Google Search",
  headings: [{ text: "Search results" }], logos: [{ text: "Google", context: "primary" }],
  controls: [], forms: [{ relevant: false, action_known: true,
    action_origin: "https://www.google.com" }], password_fields: [], sensitive_fields: [],
  inaccessible_frames: 0 };
const lookup = async token => ({ lookup_success: true, candidates: token === "google"
  ? [{ name: "Google", domain: "google.com", verified: true }] : [] });
const brand = await analyzeBrandEvidence(snapshot, url, { lookup });
const dom = analyzeDomEvidence([snapshot]);
const context = { probability, domainAgeDays: 10658, sameSite: true,
  pageRegistrableDomain: "google.com", mainSnapshot: snapshot };
assert.equal(brand.official_domain_match, true);
const decision = decideWithEvidence("DANGEROUS", dom, brand, evaluateCorrelation(dom, brand), context);
assert.equal(decision.verdict, "SAFE");
const explanation = buildAnalysisExplanation({ url, final_url: url, verdict: decision.verdict,
  model_result: { model_family: "XGBoost", verdict: "DANGEROUS" },
  decision_policy: decision, brand_features: brand, dom_features: dom });
assert.match(explanation.summary, /mengoreksi penilaian alamat/);

// A matching brand name on a different host cannot undo the URL model.
const copyUrl = "https://google.com.example.test/search?q=bca";
const copy = await analyzeBrandEvidence(snapshot, copyUrl, { lookup });
assert.equal(copy.official_domain_match, false);
assert.equal(decideWithEvidence("DANGEROUS", dom, copy, evaluateCorrelation(dom, copy),
  { ...context, pageRegistrableDomain: "example.test" }).verdict, "DANGEROUS");
console.log("Official search page correction OK; copied brand remains dangerous");
