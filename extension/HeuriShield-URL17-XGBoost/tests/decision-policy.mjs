import assert from "node:assert/strict";
import { decideWithEvidence } from "../src/analyzer/correlation/decision-policy.js";

const baseDom = { has_password_field: true, has_sensitive_input: false,
  forms: [{ relevant: true, cross_domain: false }] };
const officialBrand = { claimed_brand_status: "identified", official_domain_match: true,
  brand_domain_mismatch: false };
const unresolvedBrand = { ...officialBrand, official_domain_match: "unknown", brand_domain_mismatch: "unknown" };
const safeCorrelation = { strong_credential_impersonation: false, oauth_context: false, rules: [] };

// Official login is recorded for review. It cannot silently override URL blocking.
assert.deepEqual(decideWithEvidence("DANGEROUS", baseDom, officialBrand, safeCorrelation), {
  verdict: "DANGEROUS", source: "url_model", review_candidate: true,
  review_reason: "verified_brand_login"
});
assert.equal(decideWithEvidence("DANGEROUS", baseDom, unresolvedBrand, safeCorrelation).review_candidate, false);
assert.equal(decideWithEvidence("DANGEROUS", { ...baseDom, forms: [{ relevant: true, cross_domain: "unknown" }] }, officialBrand, safeCorrelation).review_candidate, false);
assert.equal(decideWithEvidence("SAFE", baseDom, officialBrand, safeCorrelation).verdict, "SAFE");

// A possible mismatch (R01) is not a confirmed reason to reverse SAFE.
const potential = { ...safeCorrelation, rules: [{ id: "R01", status: "matched" }] };
assert.equal(decideWithEvidence("SAFE", baseDom, unresolvedBrand, potential).verdict, "SAFE");

const corroboratedHost = { ...safeCorrelation, strong_brand_impersonation: true,
  rules: [{ id: "R09", status: "matched" }] };
assert.equal(decideWithEvidence("SAFE", { has_password_field: false, forms: [] },
  unresolvedBrand, corroboratedHost).verdict, "DANGEROUS");
assert.equal(decideWithEvidence("SAFE", { has_password_field: false, forms: [] },
  unresolvedBrand, corroboratedHost).source, "corroborated_brand_impersonation");

// Only confirmed credential impersonation (R03/R07) promotes SAFE to DANGEROUS.
const confirmed = { strong_credential_impersonation: true, oauth_context: false,
  rules: [{ id: "R03", status: "matched" }] };
assert.deepEqual(decideWithEvidence("SAFE", baseDom, { ...officialBrand, official_domain_match: false, brand_domain_mismatch: true }, confirmed), {
  verdict: "DANGEROUS", source: "confirmed_credential_impersonation", review_candidate: false, review_reason: null
});

// An observed official OAuth hop is review evidence, not a blanket allowlist.
const oauth = { ...safeCorrelation, oauth_context: true,
  rules: [{ id: "R06", status: "matched" }] };
assert.equal(decideWithEvidence("DANGEROUS", { controls: [{ type: "oauth_login" }], forms: [] }, unresolvedBrand, oauth).verdict, "DANGEROUS");
assert.equal(decideWithEvidence("DANGEROUS", { controls: [{ type: "oauth_login" }], forms: [] }, unresolvedBrand, oauth).review_candidate, true);

// A confirmed contradiction suppresses a false-positive review flag.
const contradiction = { ...safeCorrelation, rules: [{ id: "R04", status: "matched" }] };
assert.equal(decideWithEvidence("DANGEROUS", baseDom, officialBrand, contradiction).review_candidate, false);
assert.equal(decideWithEvidence("LIMITED", baseDom, officialBrand, safeCorrelation).verdict, "LIMITED");
const ownBrand = { ...unresolvedBrand, brand_claim_relation: "own_domain",
  brand_in_title: true, brand_in_heading: true };
const sameSiteDom = { ...baseDom, form_cross_domain: false };
const context = { probability: 0.5809, domainAgeDays: 1752, sameSite: true };
assert.equal(decideWithEvidence("DANGEROUS", sameSiteDom, ownBrand, safeCorrelation, context).verdict, "DANGEROUS");
assert.equal(decideWithEvidence("DANGEROUS", sameSiteDom, ownBrand, safeCorrelation,
  { ...context, parentSiteLink: true }).source, "corroborated_own_domain_review");
const noFormDom = { ...sameSiteDom, forms: [], form_cross_domain: "unknown" };
assert.equal(decideWithEvidence("DANGEROUS", noFormDom, ownBrand, safeCorrelation,
  { ...context, parentSiteLink: true }).corroboration, "parent_site_link");
assert.equal(decideWithEvidence("DANGEROUS", noFormDom, ownBrand, safeCorrelation, context).verdict, "DANGEROUS");
const copiedIdentity = { ...ownBrand, candidates: [
  { name: "Example", domain: "example.test", verified: false, claim: true, in_title: true },
  { name: "Google", domain: "google.com", verified: true, claim: true, in_title: true }
] };
assert.equal(decideWithEvidence("DANGEROUS", noFormDom, copiedIdentity, safeCorrelation,
  { ...context, pageRegistrableDomain: "example.test", parentSiteLink: true }).verdict, "DANGEROUS");
for (const bad of [
  [sameSiteDom, { ...ownBrand, brand_claim_relation: "external_domain" }, context],
  [sameSiteDom, { ...ownBrand, brand_in_title: false }, context],
  [{ ...sameSiteDom, form_cross_domain: "unknown" }, ownBrand, context],
  [{ ...sameSiteDom, forms: [] }, ownBrand, context],
  [sameSiteDom, ownBrand, { ...context, domainAgeDays: null }],
  [sameSiteDom, ownBrand, { ...context, probability: 0.8 }],
  [sameSiteDom, ownBrand, { ...context, sameSite: false }]
]) assert.equal(decideWithEvidence("DANGEROUS", bad[0], bad[1], safeCorrelation, bad[2]).verdict, "DANGEROUS");
assert.equal(decideWithEvidence("DANGEROUS", sameSiteDom, ownBrand, confirmed, context).verdict, "DANGEROUS");
// A verified first-party brand may correct a moderate URL false positive on
// its own login. A mere directory candidate, copied name, or external form may not.
const firstPartyLogin = { ...officialBrand, brand_claim_relation: "own_domain",
  claimed_brand: { name: "Example", official_domain: "example.test" },
  verified_reference_domain: "example.test", candidates: [
    { name: "Example", domain: "example.test", claim: true,
      in_title: true, in_heading: true }] };
const firstPartyDom = { ...sameSiteDom,
  forms: [{ relevant: true, cross_domain: false, same_origin: true }] };
const firstPartyContext = { ...context, mainSnapshot: { page_origin: "https://login.example.test" } };
assert.equal(decideWithEvidence("DANGEROUS", firstPartyDom, firstPartyLogin,
  safeCorrelation, firstPartyContext).source, "verified_own_domain_login");
assert.equal(decideWithEvidence("DANGEROUS", firstPartyDom,
  { ...firstPartyLogin, official_domain_match: "unknown", candidate_domain_match: true },
  safeCorrelation, firstPartyContext).verdict, "DANGEROUS");
assert.equal(decideWithEvidence("DANGEROUS", { ...firstPartyDom,
  forms: [{ relevant: true, cross_domain: true, same_origin: false }] },
  firstPartyLogin, safeCorrelation, firstPartyContext).verdict, "DANGEROUS");
assert.equal(decideWithEvidence("DANGEROUS", firstPartyDom,
  { ...firstPartyLogin, brand_claim_relation: "external_domain" },
  safeCorrelation, firstPartyContext).verdict, "DANGEROUS");
assert.equal(decideWithEvidence("DANGEROUS", firstPartyDom,
  { ...firstPartyLogin, candidates: [{ name: "Other", domain: "other.test",
    claim: true, in_title: true, in_heading: true }] },
  safeCorrelation, firstPartyContext).verdict, "DANGEROUS");
assert.equal(decideWithEvidence("DANGEROUS", firstPartyDom,
  firstPartyLogin, safeCorrelation, { ...firstPartyContext, probability: 0.8 }).verdict, "DANGEROUS");
// The long OAuth query raises URL risk, but the observed page belongs to the
// provider itself. A matching name on a lookalike host cannot receive this correction.
const oauthUrl = "https://accounts.google.com/v3/signin/accountchooser?client_id=example.apps.googleusercontent.com&redirect_uri=https%3A%2F%2Fauth.indodax.com%2F__%2Fauth%2Fhandler&response_type=code&scope=openid";
const googleBrand = { ...officialBrand, brand_claim_relation: "own_domain",
  verified_reference_domain: "google.com" };
const googleDom = { observed_frame_count: 1, form_cross_domain: false, forms: [],
  has_password_field: false, has_sensitive_input: false };
const googleContext = { sameSite: true, pageUrl: oauthUrl,
  mainSnapshot: { page_origin: "https://accounts.google.com" } };
assert.equal(decideWithEvidence("DANGEROUS", googleDom, googleBrand,
  safeCorrelation, { ...googleContext, probability: 0.99 }).source,
"verified_oauth_provider_page");
for (const [url, brand, dom, context] of [
  [oauthUrl.replace("accounts.google.com", "accounts.google.com.evil.test"), googleBrand, googleDom, googleContext],
  [oauthUrl, { ...googleBrand, official_domain_match: "unknown" }, googleDom, googleContext],
  [oauthUrl, googleBrand, { ...googleDom, observed_frame_count: 0 }, googleContext],
  [oauthUrl, googleBrand, { ...googleDom, forms: [{ relevant: true, cross_domain: true }] }, googleContext],
  ["https://auth.indodax.com/__/auth/handler?client_id=a&redirect_uri=https%3A%2F%2Findodax.com&response_type=code", googleBrand, googleDom,
    { ...googleContext, mainSnapshot: { page_origin: "https://auth.indodax.com" } }]
]) assert.equal(decideWithEvidence("DANGEROUS", dom, brand, safeCorrelation,
  { ...context, pageUrl: url }).verdict, "DANGEROUS");
assert.equal(decideWithEvidence("DANGEROUS", googleDom, googleBrand,
  confirmed, googleContext).verdict, "DANGEROUS");
// A local login shape is review metadata, even for a real site.
// A phishing site can copy its form action, logo and OAuth route.
const simakDom = { ...sameSiteDom,
  forms: [{ relevant: true, cross_domain: false, same_origin: true }],
  controls: [{ type: "oauth_login", provider: "Google",
    target_origin: "https://simak.un-sultra.ac.id", target_path: "/auth/google/redirect" }] };
const simakPage = { page_origin: "https://simak.un-sultra.ac.id",
  title: "Masuk - SIMAK UNSULTRA", logos: [{ text: "UNSULTRA Logo" }] };
const simakContext = { probability: 0.4195, domainAgeDays: 3134, sameSite: true,
  pageRegistrableDomain: "un-sultra.ac.id", mainSnapshot: simakPage };
const unknownBrand = { claimed_brand_status: "unknown", brand_domain_mismatch: "unknown", candidates: [] };
const simakReview = decideWithEvidence("DANGEROUS", simakDom, unknownBrand,
  safeCorrelation, simakContext);
assert.equal(simakReview.verdict, "DANGEROUS");
assert.equal(simakReview.review_candidate, true);
assert.equal(simakReview.review_reason, "local_login_unverified");
const copiedPage = { page_origin: "https://account-example.net",
  title: "Account Example Login", logos: [{ text: "Account Example Logo" }] };
const copiedDom = { ...simakDom, controls: [{ type: "oauth_login", provider: "Google",
  target_origin: copiedPage.page_origin, target_path: "/auth/google/redirect" }] };
assert.equal(decideWithEvidence("DANGEROUS", copiedDom, unknownBrand, safeCorrelation,
  { ...simakContext, pageRegistrableDomain: "account-example.net", mainSnapshot: copiedPage }).verdict,
  "DANGEROUS");
for (const [dom, brand, ctx] of [
  [{ ...simakDom, controls: [] }, unknownBrand, simakContext],
  [simakDom, unknownBrand, { ...simakContext, probability: 0.61 }],
  [simakDom, unknownBrand, { ...simakContext, mainSnapshot: { ...simakPage, logos: [] } }],
  [{ ...simakDom, forms: [{ relevant: true, cross_domain: true, same_origin: false }] }, unknownBrand, simakContext],
  [simakDom, { ...unknownBrand, brand_domain_mismatch: true }, simakContext],
  [simakDom, unknownBrand, { ...simakContext, domainAgeDays: null }],
  [simakDom, unknownBrand, { ...simakContext, sameSite: false }]
]) assert.equal(decideWithEvidence("DANGEROUS", dom, brand, safeCorrelation, ctx).verdict, "DANGEROUS");
console.log("Decision policy OK: URL baseline, confirmed override, review without unblocking, unknown, OAuth");
