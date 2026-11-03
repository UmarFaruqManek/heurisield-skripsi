import assert from "node:assert/strict";
import { analyzeDomEvidence, registrable } from "../src/analyzer/dom/dom-evidence.js";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { evaluateCorrelation } from "../src/analyzer/correlation/evidence-rules.js";
import { sanitizeAuditUrl } from "../src/shared/audit-url.js";

const lookup = async token => ({ lookup_success: true, candidates: ({ google: [{ name: "Google", domain: "google.com", verified: true }], github: [{ name: "GitHub", domain: "github.com", verified: true }], apple: [{ name: "Apple", domain: "apple.com", verified: true }], acme: [{ name: "Acme", domain: "acme.test", verified: true }] })[token] || [] });
const snap = (origin = "https://acme.test", changes = {}) => ({ page_origin: origin, title: "Acme account", headings: [{ text: "Sign in to Acme", in_main: true }], logos: [], controls: [], forms: [], password_fields: [], sensitive_fields: [], inaccessible_frames: 0, ...changes });
const rule = (c, id) => c.rules.find(r => r.id === id).status;
let count = 0;
async function test(id, fn) { await fn(); count++; process.stdout.write(`${id} OK\n`); }

await test("T01 official login", async () => {
  const s = snap("https://login.acme.test", { password_fields: [{ form_index: 0 }], controls: [{ type: "native_login" }] });
  const d = analyzeDomEvidence([s]); const b = await analyzeBrandEvidence(s, s.page_origin, { lookup });
  assert.equal(d.has_password_field, true); assert.equal(d.login_button_detected, true);
  assert.equal(b.official_domain_match, true); assert.equal(rule(evaluateCorrelation(d, b), "R03"), "not_matched");
});
await test("T02 third party Google button", async () => {
  const s = snap("https://shop.test", { title: "Sign in with Google", headings: [{ text: "Continue with Google" }], controls: [{ type: "oauth_login", provider: "Google" }] });
  const b = await analyzeBrandEvidence(s, s.page_origin, { lookup });
  assert.equal(b.claimed_brand, null); assert.equal(analyzeDomEvidence([s]).login_button_detected, true);
});
await test("T03 observed GitHub OAuth navigation", async () => {
  const s = snap("https://app.test", { controls: [{ type: "oauth_login", provider: "GitHub" }] });
  const d = analyzeDomEvidence([s], { observed: true, destination_type: "official_provider" });
  const b = await analyzeBrandEvidence(s, s.page_origin, { lookup });
  assert.equal(d.login_redirect_detected, true); assert.equal(rule(evaluateCorrelation(d, b), "R06"), "matched");
});
await test("T04 Apple provider is not claimed app", async () => {
  const s = snap("https://shop.test", { title: "Store", headings: [], controls: [{ type: "oauth_login", provider: "Apple" }] });
  assert.equal((await analyzeBrandEvidence(s, s.page_origin, { lookup })).claimed_brand, null);
});
await test("T05 fake provider not rescued by OAuth", async () => {
  const s = snap("https://google-login.example.test", { title: "Google Login", headings: [{ text: "Sign in to Google" }], password_fields: [{ form_index: 0 }] });
  const b = await analyzeBrandEvidence(s, s.page_origin, { lookup });
  assert.equal(b.official_domain_match, false); assert.equal(b.brand_domain_mismatch, "unknown");
  assert.equal(rule(evaluateCorrelation(analyzeDomEvidence([s]), b), "R06"), "not_matched");
  // A confirmed mismatch is synthetic here; the live analyzer only reports potential mismatch.
  const confirmed = { ...b, brand_domain_mismatch: true };
  assert.equal(rule(evaluateCorrelation(analyzeDomEvidence([s]), confirmed), "R03"), "matched");
  assert.equal(rule(evaluateCorrelation(analyzeDomEvidence([s]), confirmed), "R07"), "matched");
});
await test("T06 provider logo in footer", async () => {
  const s = snap("https://shop.test", { title: "Shop", headings: [], logos: [{ text: "Google", context: "footer" }] });
  assert.equal((await analyzeBrandEvidence(s, s.page_origin, { lookup })).claimed_brand, null);
});
await test("T07 relative form action", () => {
  const d = analyzeDomEvidence([snap("https://acme.test", { forms: [{ relevant: true, action_known: true, action_origin: "https://acme.test" }] })]);
  assert.equal(d.form_cross_domain, false);
});
await test("T08 external SSO is not phishing on its own", () => {
  const d = analyzeDomEvidence([snap("https://acme.test", { forms: [{ relevant: true, action_known: true, action_origin: "https://sso.vendor.test" }] })]);
  assert.equal(d.form_cross_domain, true);
  assert.notEqual(rule(evaluateCorrelation(d, { claimed_brand_status: "unknown", official_domain_match: "unknown" }), "R04"), "matched");
});
await test("T09 unresolved JS submit", () => {
  assert.equal(analyzeDomEvidence([snap("https://acme.test", { forms: [{ relevant: true, action_known: false, action_origin: null }] })]).form_cross_domain, "unknown");
});
await test("T10 OTP without password", () => {
  const d = analyzeDomEvidence([snap("https://acme.test", { sensitive_fields: [{ type: "otp" }] })]);
  assert.equal(d.has_password_field, false); assert.equal(d.has_sensitive_input, true);
});
await test("T11 modal update", () => {
  const s = snap(); assert.equal(analyzeDomEvidence([s]).has_password_field, false);
  assert.equal(analyzeDomEvidence([{ ...s, password_fields: [{ form_index: 0 }], controls: [{ type: "native_login" }] }]).has_password_field, true);
});
await test("T12 inaccessible iframe", () => {
  assert.equal(analyzeDomEvidence([snap("https://acme.test", { inaccessible_frames: 1 })]).has_password_field, "unknown");
});
await test("T13 deceptive subdomain", async () => {
  const s = snap("https://google.com.example.test", { title: "Google Login", headings: [{ text: "Sign in to Google" }] });
  assert.equal((await analyzeBrandEvidence(s, s.page_origin, { lookup })).official_domain_match, false);
  assert.equal(registrable(s.page_origin), "example.test");
});
await test("T14 returning app remains evaluated", () => {
  const d = analyzeDomEvidence([snap("https://app.test")], { observed: true, destination_type: "same_site" });
  assert.notEqual(rule(evaluateCorrelation(d, { claimed_brand_status: "unknown", official_domain_match: "unknown" }), "R06"), "matched");
});
await test("T15 article mention not a claim", async () => {
  const s = snap("https://blog.test", { title: "Tutorial Login Google", headings: [{ text: "Cara masuk Google" }] });
  assert.equal((await analyzeBrandEvidence(s, s.page_origin, { lookup })).claimed_brand, null);
});
await test("T16 unavailable official mapping stays unknown", async () => {
  const s = snap("https://different.test");
  const b = await analyzeBrandEvidence(s, s.page_origin, { lookup: async token => ({ lookup_success: true, candidates: token === "acme" ? [{ name: "Acme", domain: "acme.test" }] : [] }) });
  assert.equal(b.official_domain_match, "unknown"); assert.equal("authorized_domain_match" in b, false); assert.equal(b.brand_domain_mismatch, "unknown");
});
await test("T17 lookalike provider not official", async () => {
  const s = snap("https://app.test", { controls: [{ type: "oauth_login", provider: "Google" }] });
  const d = analyzeDomEvidence([s], { observed: true, destination_type: "unverified" });
  const b = await analyzeBrandEvidence(s, s.page_origin, { lookup });
  assert.notEqual(rule(evaluateCorrelation(d, b), "R06"), "matched");
});
await test("T18 OAuth secrets excluded", () => {
  const value = sanitizeAuditUrl("https://app.test/callback?code=secret123&state=abc&token=xyz&view=ok#access_token=hidden");
  assert.equal(value, "https://app.test/callback?view=ok");
});
await test("T19 page-local brand claim alone does not confirm credential impersonation", () => {
  const dom = { has_password_field: true, has_sensitive_input: false, forms: [], controls: [] };
  const brand = { claimed_brand_status: "identified", official_domain_match: false,
    brand_domain_mismatch: "unknown",
    high_confidence_credential_impersonation: true, host_brand_claim: "unknown" };
  assert.notEqual(rule(evaluateCorrelation(dom, brand), "R10"), "matched");
  assert.equal(evaluateCorrelation(dom, brand).strong_credential_impersonation, false);
  assert.equal(rule(evaluateCorrelation(dom, { ...brand, host_brand_claim: "lookalike" }), "R10"), "matched");
});
assert.equal(count, 19);
