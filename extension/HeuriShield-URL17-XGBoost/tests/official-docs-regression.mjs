import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { extractUrl18Features } from "../src/analyzer/url/url18-features.js";
import { predictProbability } from "../src/model/xgboost-engine.js";
import { analyzeDomEvidence } from "../src/analyzer/dom/dom-evidence.js";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { evaluateCorrelation } from "../src/analyzer/correlation/evidence-rules.js";
import { decideWithEvidence } from "../src/analyzer/correlation/decision-policy.js";

const model = JSON.parse(readFileSync(new URL("../src/model/xgboost-url18.json", import.meta.url)));
const url = "https://antigravity.google/docs/changelog";
const actualProbability = predictProbability(model,
  { ...extractUrl18Features(url), domain_age_days: 400 });
assert.ok(actualProbability >= 0 && actualProbability <= 1);
// Exercise the correction boundary independently of this newly trained model.
const probability = 0.85;
const snapshot = { page_origin: "https://antigravity.google",
  title: "Changelog | Google Antigravity", headings: [{ text: "Changelog" }],
  logos: [{ text: "Google Antigravity", context: "primary" }],
  controls: [], forms: [], password_fields: [], sensitive_fields: [],
  inaccessible_frames: 0 };
const lookup = async token => ({ lookup_success: true,
  candidates: token === "antigravity" || token === "google" ?
    [{ name: "Google Antigravity", domain: "antigravity.google", verified: true }] : [] });
const brand = await analyzeBrandEvidence(snapshot, url, { lookup });
const dom = analyzeDomEvidence([snapshot]);
const correlation = evaluateCorrelation(dom, brand);
const context = { pageUrl: url, mainSnapshot: snapshot, probability,
  domainAgeDays: 400, sameSite: true, pageRegistrableDomain: "antigravity.google" };
assert.equal(brand.official_domain_match, true);
assert.equal(decideWithEvidence("DANGEROUS", dom, brand, correlation, context).source,
  "verified_own_domain_documentation_page");
for (const [badDom, badBrand, badContext] of [
  [{ ...dom, has_password_field: true }, brand, context],
  [{ ...dom, has_sensitive_input: "unknown" }, brand, context],
  [dom, { ...brand, official_domain_match: "unknown" }, context],
  [dom, brand, { ...context, pageUrl: "https://antigravity.google/login" }],
  [dom, brand, { ...context, pageRegistrableDomain: "example.test" }],
  [dom, brand, { ...context, probability: 0.95 }],
  [dom, brand, { ...context, sameSite: false }]
]) assert.equal(decideWithEvidence("DANGEROUS", badDom, badBrand,
  evaluateCorrelation(badDom, badBrand), badContext).verdict, "DANGEROUS");
console.log("Verified documentation correction and phishing safeguards OK");
