import assert from "node:assert/strict";
import { searchBrandfetch, searchClearbit } from "../src/analyzer/brand/brand-features.js";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { analyzeDomEvidence } from "../src/analyzer/dom/dom-evidence.js";
let calls = 0;
globalThis.fetch = async () => {
  calls++;
  return { ok: false, status: 429, headers: { get: () => "120" } };
};
const limited = await searchBrandfetch("test", { apiUrl: "https://brandfetch.mock/{query}" });
assert.equal(limited.status, "rate_limited");
assert.equal(limited.http_status, 429);
assert.equal(limited.retry_after_ms, 120000);
const cooled = await searchBrandfetch("other", { apiUrl: "https://brandfetch.mock/{query}" });
assert.equal(cooled.status, "provider_cooldown");
assert.equal(calls, 1);
globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => [] });
const empty = await searchClearbit("test", { apiUrl: "https://clearbit.mock/?q={token}" });
assert.equal(empty.status, "no_match");
assert.equal(empty.lookup_success, true);
globalThis.fetch = async () => { const error = new Error("timeout"); error.name = "AbortError"; throw error; };
assert.equal((await searchClearbit("test", { apiUrl: "https://timeout.mock/?q={token}" })).status, "timeout");
const snapshot = { title: "Microsoft | Login", headings: [], logos: [],
  password_fields: [{ form_index: 0 }], controls: [{ type: "native_login" }], forms: [] };
const brand = await analyzeBrandEvidence(snapshot, "https://storage.example.test/file", {
  lookup: async token => ({ lookup_success: true, candidates: token === "microsoft" ?
    [{ name: "Microsoft", domain: "microsoft.com", verified: false }] : [] }) });
assert.equal(brand.claimed_brand?.name, "Microsoft");
assert.equal(brand.candidate_reference_domain, "microsoft.com");
assert.equal(brand.reference_status, "provider_verified");
assert.equal(brand.official_domain_match, false);
assert.equal(brand.high_confidence_credential_impersonation, true);
assert.equal(analyzeDomEvidence([{ evidence_incomplete: true, forms: [], password_fields: [] }]).has_password_field, "unknown");
assert.equal(analyzeDomEvidence([{ evidence_incomplete: true, password_fields: [{}] }]).has_password_field, true);
console.log("API diagnostics/cooldown, credential title claim and incomplete DOM checks passed");
