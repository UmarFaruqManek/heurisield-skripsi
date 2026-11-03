import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {searchBrand,searchClearbit,extractBrandFeatureSet,pathBrandTokens,topBrandCandidate} from '../src/analyzer/brand/brand-features.js';
import {buildFeatureVector} from '../src/analyzer/feature-assembler.js';
import {evaluateRuleFitEngine} from '../src/rule/rulefit-engine.js';
const originalFetch=globalThis.fetch;
const options={clearbit:{timeoutMs:20},brandfetch:{timeoutMs:20}};
let calls=[];
function mock(clearbit,brandfetch) {
  calls=[];
  globalThis.fetch=async (url)=>{
    calls.push(String(url));
    const value=String(url).includes('clearbit')?clearbit:brandfetch;
    if(value instanceof Error) throw value;
    return {ok:true,json:async()=>value};
  };
}
try {
  const dicodingUrl='https://www.dicoding.com/login/mfa-verification';
  assert.deepEqual(pathBrandTokens('/login/mfa-verification'),[]);
  const dicodingBrand=await extractBrandFeatureSet({
    originalUrl:dicodingUrl,
    title:'Verifikasi Two-Factor Authentication (2FA) Diperlukan',
    lookup:async query=>({query,lookup_success:true,candidates:query==='dicoding'
      ? [{name:'Dicoding',domain:'dicoding.com',source:'brandfetch',_score:20,qualityScore:.7}]
      : query==='mfa' ? [{name:'Museum of Fine Arts, Boston',domain:'mfa.org',source:'clearbit'}] : []})
  });
  assert.equal(dicodingBrand.brand_top_candidate_domain,'dicoding.com');
  assert.equal(dicodingBrand.brand_matches_page,true);
  const competingBrand=topBrandCandidate([
    {query:'mfa',candidates:[{name:'Museum of Fine Arts, Boston',domain:'mfa.org',source:'clearbit'}]},
    {query:'dicoding',candidates:[{name:'Dicoding',domain:'dicoding.com',source:'brandfetch'}]}
  ],dicodingUrl,dicodingUrl);
  assert.equal(competingBrand.brand_top_candidate_domain,'dicoding.com');

  mock([{name:'Roblox',domain:'roblox.com'}],[{name:'Roblox',domain:'roblox.com',_score:120,qualityScore:.96}]);
  const result=await searchBrand('Roblox',options);
  assert.ok(calls[0].includes('autocomplete.clearbit.com'));
  assert.ok(calls[1].includes('api.brandfetch.io'));
  assert.equal(result.candidates[0].source,'clearbit');
  assert.equal(result.candidates[0]._score,120);
  assert.equal(result.candidates[0].qualityScore,.96);
  assert.equal(result.candidates[0].score_source,'brandfetch');

  mock([{name:'Roblox',domain:'roblox.com'}],[{name:'Different brand',domain:'other.example',_score:999,qualityScore:1}]);
  const unmatched=await searchBrand('Roblox',options);
  assert.equal(unmatched.candidates[0]._score,null);
  assert.equal(unmatched.candidates[0].qualityScore,null);
  assert.equal(unmatched.candidates[0].score_source,null);

  for (const primary of [[],{},new Error('offline'),[{name:'Invalid',domain:'localhost'}]]) {
    mock(primary,[{name:'Roblox',domain:'roblox.com',_score:120,qualityScore:.96}]);
    const fallback=await searchBrand('Roblox',options);
    assert.equal(fallback.candidates[0].source,'brandfetch');
  }
  mock([{name:'Roblox',domain:'roblox.com'}],new Error('offline'));
  const primaryOnly=await searchBrand('Roblox',options);
  assert.equal(primaryOnly.candidates[0].source,'clearbit');
  assert.equal(primaryOnly.candidates[0]._score,null);
  assert.equal(primaryOnly.candidates[0].qualityScore,null);

  mock(new Error('offline'),new Error('offline'));
  assert.equal((await searchBrand('Roblox',options)).lookup_success,false);
  const features=await extractBrandFeatureSet({originalUrl:'https://roblox.attacker.example/login',lookup:async()=>primaryOnly});
  assert.equal(features.brand_top_candidate_source,'clearbit');
  assert.equal(features.brand_matches_page,false);
  assert.equal(features.brand_in_source_subdomain,true);
  assert.equal(features.brand_quality_score,null);
  const contract=JSON.parse(await readFile(new URL('../src/rule/feature-contract-60.json',import.meta.url),'utf8'));
  const engine=JSON.parse(await readFile(new URL('../src/rule/rulefit-engine-60.json',import.meta.url),'utf8'));
  const assembled=buildFeatureVector(contract.features,{brand:features});
  assert.equal(assembled.feature_count,60);
  assert.equal(assembled.vector.brand_search_score,null);
  const imputed=Object.fromEntries(contract.features.map(f=>[f,assembled.vector[f]??engine.imputer_median[f]]));
  const decision=evaluateRuleFitEngine(engine,assembled.vector);
  assert.equal(decision.rule_count,150);
  assert.equal(decision.threshold,.8);
  assert.equal(decision.probability_phishing,evaluateRuleFitEngine(engine,imputed).probability_phishing);

  mock([{name:'Acme',domain:'acme.example'}],[]);
  await searchClearbit('Acme & Co');
  assert.equal(new URL(calls[0]).searchParams.get('query'),'Acme & Co');
  calls=[];
  assert.equal((await searchBrand('  ',options)).lookup_success,false);
  assert.equal(calls.length,0);

  calls=[];
  globalThis.fetch=async (url,{signal})=>{
    calls.push(String(url));
    if(!String(url).includes('clearbit'))return {ok:true,json:async()=>[{name:'Roblox',domain:'roblox.com',_score:120,qualityScore:.96}]};
    return {ok:true,json:()=>new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(new Error('timeout')),{once:true}))};
  };
  const timeout=await searchBrand('Roblox',options);
  assert.equal(timeout.candidates[0].source,'brandfetch');
  console.log('brand-provider-order: PASS (order, fallback, matching-domain scores, missing values, encoding, body timeout)');
} finally {globalThis.fetch=originalFetch;}
