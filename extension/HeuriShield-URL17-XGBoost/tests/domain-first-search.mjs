import assert from "node:assert/strict";
import { searchDomainBrand } from "../src/analyzer/brand/domain-brand-search.js";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
const response = (name,domain) => ({lookup_success:true,candidates:[{name,domain,source:"fixture",verified:false}]});
const calls=[];
const domain = await searchDomainBrand("dicoding.com", {
  clearbit: async q => {calls.push(`clearbit:${q}`);return response("Dicoding","dicoding.com");},
  brandfetch: async () => {throw Error("unneeded fallback");},
  domainLookup: async () => {throw Error("unneeded fallback");}
});
assert.equal(domain.found,true);
assert.deepEqual(calls,["clearbit:dicoding.com"]);
let tokenCalls=0;
const page={title:"Dicoding",headings:[{text:"Dicoding Academy"}],logos:[],password_fields:[],controls:[]};
const own=await analyzeBrandEvidence(page,"https://portal.dicoding.com",{
  domainSearch:async root=>{assert.equal(root,"dicoding.com");return domain;},
  lookup:async()=>{tokenCalls++;return {lookup_success:true,candidates:[]};}
});
assert.equal(tokenCalls,0);
assert.equal(own.claimed_brand.name,"Dicoding");
assert.equal(own.candidate_domain_match,true);
assert.equal(own.official_domain_match,"unknown");
assert.equal(own.token_fallback_used,false);
const order=[];
const fallback=await searchDomainBrand("example.test",{
  clearbit:async()=>{order.push("clearbit");return response("Wrong","wrong.test");},
  brandfetch:async()=>{order.push("brandfetch");return {lookup_success:false,status:"rate_limited",candidates:[]};},
  domainLookup:async()=>{order.push("heurishield");return {lookup_success:true,found:true,registrable_domain:"example.test",brand_name:"Example",brand_verified:false};}
});
assert.deepEqual(order,["clearbit","brandfetch","heurishield"]);
assert.equal(fallback.candidates[0].domain,"example.test");
const conflict=await analyzeBrandEvidence({title:"Login BCA",headings:[{text:"Masuk ke BCA"}],
  logos:[],password_fields:[{}],controls:[{type:"native_login"}]},"https://bca.bank.com/login",{
  domainSearch:async()=>({queried_domain:"bank.com",lookup_success:true,found:true,candidates:[{name:"Bank",domain:"bank.com",verified:false}]}),
  lookup:async q=>q==="bca"?{lookup_success:true,candidates:[{name:"BCA",domain:"bca.co.id",verified:true}]}:{lookup_success:true,candidates:[]}
});
assert.equal(conflict.token_fallback_used,true);
assert.equal(conflict.claimed_brand.name,"BCA");
assert.equal(conflict.high_confidence_host_impersonation,true);
console.log("Domain-first search: exact domain, lazy fallback, provider failure, and conflicting identity passed");
