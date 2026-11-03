import assert from 'node:assert/strict';
import { buildAnalysisExplanation as explain } from '../src/shared/analysis-explanation.js';

const mismatch = { brand_found: true, brand_top_candidate_name: 'Facebook',
  brand_top_candidate_domain: 'facebook.com', brand_matches_page: false };
const irrelevant = explain({
  verdict: 'DANGEROUS', hostname: 'www.dicoding.com', brand_features: {
    ...mismatch, brand_top_candidate_name: 'Museum of Fine Arts, Boston',
    brand_top_candidate_domain: 'mfa.org', brand_top_candidate_query_priority: 20
  },
  dom_features: { external_credential_form_count: 1 },
  url_features: { final_domain_changed: true },
  model_result: { ready: true, raw_verdict: 'DANGEROUS', fired_rules: [] }
});
assert.equal(irrelevant.reasons.length, 1);
assert.doesNotMatch(irrelevant.reasons[0], /MFA|mfa\.org|form|mengalihkan/);
assert.match(irrelevant.reasons[0], /Belum ada satu temuan/);

const guard = explain({ verdict: 'DANGEROUS', model_result: {
  ready: true, raw_verdict: 'SAFE', post_model_guard: { id: 'BRAND_IMPERSONATION_GUARD',
    active_domain: 'roblox.ss', official_domain: 'roblox.com', brand: 'Roblox' }
}});
assert.match(guard.reasons[0], /roblox.ss.*Roblox.*roblox.com/);
assert.equal(guard.reasons.length, 1);

const rule = explain({ verdict: 'DANGEROUS', hostname: 'www.roblox.ss',
  url_features: { final_registrable_domain: 'roblox.ss' }, brand_features: {
    brand_found: true, brand_top_candidate_name: 'Roblox',
    brand_top_candidate_domain: 'roblox.com', brand_matches_page: false
  },
  rdap_features: { final_rdap_available: true, page_domain_age_days: 16 },
  model_result: { ready: true, raw_verdict: 'DANGEROUS', fired_rules: [
    { coefficient: 2, conditions: [{ feature: 'brand_matches_page', operator: '<=', value: 0, passed: true }] },
    { coefficient: 1.5, conditions: [{ feature: 'page_domain_age_days', operator: '<=', value: 16, passed: true }] }
  ]}
});
assert.equal(rule.reasons.length, 2);
assert.match(rule.reasons[0], /roblox.com/);
assert.match(rule.reasons[1], /16 hari/);

const imputed = explain({ verdict: 'DANGEROUS',
  rdap_features: { final_rdap_available: true, page_domain_age_days: 16 },
  model_result: { ready: true, raw_verdict: 'DANGEROUS', fired_rules: [
    { coefficient: 1, conditions: [{ feature: 'page_domain_age_days', operator: '<=', value: null,
      imputed_value: 16, passed: true }] }
  ]}
});
assert.doesNotMatch(imputed.reasons[0], /16 hari/);

const safe = explain({ verdict: 'SAFE', model_result: { ready: true },
  brand_features: { ...mismatch, brand_matches_page: true },
  dom_features: { external_credential_form_count: 0, ip_credential_form_count: 0 } });
assert.equal(safe.reasons.length, 1);
assert.match(safe.reasons[0], /di bawah batas risiko/);
assert.equal(explain({ verdict: 'DANGEROUS',
  matched_rules: [{ id: 'MANUAL_BLOCKLIST' }] }).reasons.length, 1);
console.log('Explanation decision relevance tests passed.');
