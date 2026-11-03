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
  { ...context, pageUrl: copyUrl, pageRegistrableDomain: "example.test",
    mainSnapshot: { ...snapshot, page_origin: "https://google.com.example.test" } }).verdict, "DANGEROUS");

// A long search URL can exceed the URL threshold while a cross-origin iframe
// is unreadable. Unknown iframe contents must not become a claim that a
// credential form exists, but an observed account form must still block.
const kendariUrl = "https://www.google.com/search?q=kendari&oq=kendari&gs_lcrp=EgZjaHJvbWUqDQgAEAAY4wIYsQMYgAQyDQgAEAAY4wIYsQMYgAQyCggBEC4YsQMYgAQyCggCEAAYsQMYgAQyBwgDEAAYgAQyDQgEEAAYgwEYsQMYgAQyBggFEEUYPDIGCAYQRRg8MgYIBxBFGDzSAQgxMDE5ajBqN6gCALACAA&sourceid=chrome&source=chrome.ob&ie=UTF-8";
const kendariProbability = predictProbability(model,
  { ...extractUrl18Features(kendariUrl), domain_age_days: 10658 });
assert.ok(kendariProbability >= model.threshold && kendariProbability < 0.6);
const incompleteSnapshot = { ...snapshot, title: "kendari - Google Search",
  logos: [],
  forms: [{ relevant: false, action_known: true, action_origin: "https://www.google.com" }],
  inaccessible_frames: 1 };
const incompleteBrand = await analyzeBrandEvidence(incompleteSnapshot, kendariUrl, { lookup });
assert.equal(incompleteBrand.brand_in_title, true);
const incompleteDom = analyzeDomEvidence([incompleteSnapshot]);
assert.equal(incompleteDom.form_cross_domain, "unknown");
const incompleteContext = { ...context, pageUrl: kendariUrl,
  mainSnapshot: incompleteSnapshot, probability: kendariProbability };
const incompleteCorrelation = evaluateCorrelation(incompleteDom, incompleteBrand);
const corrected = decideWithEvidence("DANGEROUS", incompleteDom, incompleteBrand,
  incompleteCorrelation, incompleteContext);
assert.equal(corrected.source, "verified_own_domain_search_page");
const correctedText = buildAnalysisExplanation({ url: kendariUrl,
  final_url: kendariUrl, verdict: corrected.verdict,
  model_result: { model_family: "XGBoost", verdict: "DANGEROUS" },
  decision_policy: corrected, brand_features: incompleteBrand,
  dom_features: incompleteDom });
assert.match(correctedText.reasons.join(" "), /sebagian iframe belum dapat diperiksa/i);
assert.doesNotMatch(correctedText.reasons.join(" "), /tujuan pengiriman data akun belum dapat dipastikan/i);

// Search results can mention an unrelated verified brand in both title and
// heading. That name is the subject of the search, not the site's identity.
const prabowoUrl = "https://www.google.com/search?q=prabowo&oq=prabowo&gs_lcrp=EgZjaHJvbWUqEAgAEAAYgwEY4wIYsQMYgAQyEAgAEAAYgwEY4wIYsQMYgAQyDQgBEC4YgwEYsQMYgAQyEggCEAAYQxiDARixAxiABBiKBTIPCAMQABhDGLEDGIAEGIoFMg0IBBAAGIMBGLEDGIAEMgYIBRBFGD0yBggGEEUYPTIGCAcQRRg90gEIMTExMWowajeoAgCwAgA&sourceid=chrome&source=chrome.ob&ie=UTF-8";
const prabowoProbability = predictProbability(model,
  { ...extractUrl18Features(prabowoUrl), domain_age_days: 10658 });
assert.ok(prabowoProbability >= model.threshold && prabowoProbability < 0.6);
const searchSnapshot = { ...incompleteSnapshot,
  title: "prabowo - Google Search", headings: [{ text: "Prabowo" }],
  forms: [{ relevant: true, action_known: false, action_origin: null }] };
const searchLookup = async token => ({ lookup_success: true, candidates:
  token === "google" ? [{ name: "Google", domain: "google.com", verified: true }]
    : token === "prabowo" ? [{ name: "Prabowo", domain: "prabowo.id", verified: true }]
      : [] });
const searchBrand = await analyzeBrandEvidence(searchSnapshot, prabowoUrl,
  { lookup: searchLookup });
const searchDom = analyzeDomEvidence([searchSnapshot]);
assert.equal(searchBrand.official_domain_match, true);
assert.ok(searchBrand.candidates.some(candidate => candidate.name === "Prabowo" && candidate.claim));
assert.equal(searchDom.form_cross_domain, "unknown");
const searchContext = { ...incompleteContext, pageUrl: prabowoUrl,
  mainSnapshot: searchSnapshot, probability: prabowoProbability };
assert.equal(decideWithEvidence("DANGEROUS", searchDom, searchBrand,
  evaluateCorrelation(searchDom, searchBrand), searchContext).verdict, "SAFE");
const searchExplanation = buildAnalysisExplanation({ url: prabowoUrl,
  final_url: prabowoUrl, verdict: "SAFE",
  model_result: { model_family: "XGBoost", verdict: "DANGEROUS" },
  decision_policy: { source: "verified_own_domain_search_page" },
  brand_features: searchBrand, dom_features: searchDom });
assert.match(searchExplanation.reasons.join(" "), /jenis data dan tujuan formulir/);
for (const [badDom, badBrand, badContext] of [
  [{ ...incompleteDom, forms: [{ relevant: true, cross_domain: true,
    destination_verification: false }] },
    incompleteBrand, incompleteContext],
  [{ ...incompleteDom, has_password_field: true }, incompleteBrand, incompleteContext],
  [{ ...incompleteDom, has_sensitive_input: true }, incompleteBrand, incompleteContext],
  [incompleteDom, { ...incompleteBrand, official_domain_match: "unknown" }, incompleteContext],
  [incompleteDom, incompleteBrand, { ...incompleteContext, pageUrl: "https://www.google.com/login?q=kendari" }],
  [incompleteDom, incompleteBrand, { ...incompleteContext, sameSite: false }]
]) assert.equal(decideWithEvidence("DANGEROUS", badDom, badBrand,
  evaluateCorrelation(badDom, badBrand), badContext).verdict, "DANGEROUS");
console.log("Official search page correction and inaccessible iframe safeguards OK");
