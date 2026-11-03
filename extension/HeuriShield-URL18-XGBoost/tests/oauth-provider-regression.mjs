import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { extractUrl18Features } from "../src/analyzer/url/url18-features.js";
import { predictProbability } from "../src/model/xgboost-engine.js";
import { analyzeDomEvidence } from "../src/analyzer/dom/dom-evidence.js";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { evaluateCorrelation } from "../src/analyzer/correlation/evidence-rules.js";
import { decideWithEvidence } from "../src/analyzer/correlation/decision-policy.js";

const model = JSON.parse(readFileSync(new URL("../src/model/xgboost-url18.json", import.meta.url)));
const state = Array.from({ length: 1800 }, (_, index) =>
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[(index * 47 + Math.floor(index / 7) * 19) % 64]).join("");
const url = `https://accounts.google.com/v3/signin/accountchooser?client_id=932505930808-example.apps.googleusercontent.com&context_uri=https%3A%2F%2Findodax.com&prompt=select_account&redirect_uri=https%3A%2F%2Fauth.indodax.com%2F__%2Fauth%2Fhandler&response_type=code&scope=openid+email+profile&state=${state}&service=lso&flowName=GeneralOAuthFlow&app_domain=https%3A%2F%2Fauth.indodax.com`;
const snapshot = { page_origin: "https://accounts.google.com", title: "Sign in with Google",
  headings: [{ text: "Choose an account" }], logos: [{ text: "Google", context: "primary" }],
  controls: [], forms: [], password_fields: [], sensitive_fields: [], inaccessible_frames: 0 };
const lookup = async token => ({ lookup_success: true, candidates: token === "google" ?
  [{ name: "Google", domain: "google.com", verified: true, source: "existing_oauth_provider_domains" }] : [] });
const probability = predictProbability(model, { ...extractUrl18Features(url), domain_age_days: 10658 });
const brand = await analyzeBrandEvidence(snapshot, url, { lookup });
const dom = analyzeDomEvidence([snapshot]);
assert.equal(brand.official_domain_match, true);
const context = { probability, domainAgeDays: 10658, sameSite: true,
  pageRegistrableDomain: "google.com", pageUrl: url, mainSnapshot: snapshot };
const decision = decideWithEvidence("DANGEROUS", dom, brand,
  evaluateCorrelation(dom, brand), context);
assert.equal(decision.source, "verified_oauth_provider_page");
assert.equal(decision.verdict, "SAFE");

const fake = url.replace("accounts.google.com", "accounts.google.com.evil.test");
const fakeSnapshot = { ...snapshot, page_origin: "https://accounts.google.com.evil.test" };
const fakeBrand = await analyzeBrandEvidence(fakeSnapshot, fake, { lookup });
const fakeDom = analyzeDomEvidence([fakeSnapshot]);
assert.equal(decideWithEvidence("DANGEROUS", fakeDom, fakeBrand,
  evaluateCorrelation(fakeDom, fakeBrand),
  { ...context, pageUrl: fake, pageRegistrableDomain: "evil.test",
    mainSnapshot: fakeSnapshot }).verdict, "DANGEROUS");
console.log("OAuth provider regression OK; model score", probability.toFixed(3));
