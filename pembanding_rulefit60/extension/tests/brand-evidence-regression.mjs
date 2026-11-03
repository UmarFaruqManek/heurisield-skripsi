import assert from 'node:assert/strict';
import { detectBrandImpersonationGuard } from '../src/analyzer/runtime-analysis.js';
import { extractCrawlerUrlFeatureSet } from '../src/analyzer/url/url-features.js';
import { brandRelationshipFields, topBrandCandidate } from '../src/analyzer/brand/brand-features.js';
function check(url, official, expected) {
  const brand = {brand_found:true,brand_top_candidate_domain:official,
    ...brandRelationshipFields(official,url,url)};
  assert.equal(Boolean(detectBrandImpersonationGuard(brand,extractCrawlerUrlFeatureSet({originalUrl:url}))),expected,url);
}
check('https://www.gov.uk/log-in-register-hmrc-online-services','register.it',false);
check('https://covenant.edu/admissions/apply.html','admissions.cn',false);
check('https://www.ssa.gov/medicare/part-d-extra-help','medicare.gov',false);
check('https://www.hsbc.co.uk/help/payment','hsbc.com',false);
check('https://humboldt-wi.gov/forms-permits/','humboldtwild.org',false);
check('https://www.roblox.com.bi/login','roblox.com',true);
check('https://facebook.example.net/login','facebook.com',true);
check('https://www.roblox.com/login','roblox.com',false);
const result=topBrandCandidate([{query:'register',candidates:[{domain:'register.it',name:'Register.it',source:'clearbit'}]}],'https://gov.uk/register','https://gov.uk/register');
assert.equal(result.brand_found,false);
console.log('9 brand evidence regression checks passed');
