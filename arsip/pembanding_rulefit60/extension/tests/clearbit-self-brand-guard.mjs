import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {buildRuntimeFeatureAnalysis} from '../src/analyzer/runtime-analysis.js';
import {normalizeRdapResponse} from '../src/analyzer/domain/rdap-features.js';
const featureContract=JSON.parse(await readFile(new URL('../src/rule/feature-contract-60.json',import.meta.url),'utf8'));
const diagnosticModel={model_family:'RuleFit',threshold:.8,intercept:5,imputer_median:{},rules:[]};
async function analyze(overrides={}) {
  const options={
    originalUrl:'https://www.roblox.com/',finalUrl:'https://www.roblox.com/',title:'Roblox',
    domFeatures:{external_credential_form_count:0,ip_credential_form_count:0},
    httpStatusCode:200,featureContract,rulefitEngine:diagnosticModel,
    rdapLookup:async()=>normalizeRdapResponse({domain:'roblox.com',creationDate:'2004-01-01T00:00:00Z'}),
    brandLookup:async query=>({query,lookup_success:true,candidates:query==='roblox'?[{name:'Roblox',domain:'roblox.com',source:'clearbit',_score:null,qualityScore:null}]:[]}),
    ...overrides
  };
  return buildRuntimeFeatureAnalysis(options);
}
const clearbitOnly=await analyze();
assert.equal(clearbitOnly.model_result.verdict,'SAFE');
assert.equal(clearbitOnly.model_result.original_verdict,'DANGEROUS');
assert.equal(clearbitOnly.brand_features.brand_quality_score,null);
assert.equal(clearbitOnly.model_result.post_model_guard.id,'SELF_BRAND_DOMAIN_GUARD');

const enriched=await analyze({brandLookup:async query=>({query,lookup_success:true,candidates:query==='roblox'?[{name:'Roblox',domain:'roblox.com',source:'clearbit',score_source:'brandfetch',_score:120,qualityScore:.96}]:[]})});
assert.equal(enriched.model_result.verdict,'SAFE');

for(const overrides of [
  {domFeatures:null},
  {domFeatures:{}},
  {domFeatures:{external_credential_form_count:1,ip_credential_form_count:0}},
  {domFeatures:{external_credential_form_count:0,ip_credential_form_count:1}},
  {title:'Unrelated page'},
  {httpStatusCode:404},
  {originalUrl:'https://roblox.attacker.example/login'},
  {originalUrl:'https://www.roblox.com.bi/login',finalUrl:'https://www.roblox.com.bi/login'},
  {rdapLookup:async()=>({rdap_available:false})},
  {rdapLookup:async()=>normalizeRdapResponse({domain:'roblox.com',creationDate:new Date().toISOString()})}
]) {
  const result=await analyze(overrides);
  assert.equal(result.model_result.verdict,'DANGEROUS',JSON.stringify(overrides));
}
console.log('clearbit-self-brand-guard: PASS (exact domain, title, RDAP, known DOM, form targets, no cross-domain redirect, missing scores)');
