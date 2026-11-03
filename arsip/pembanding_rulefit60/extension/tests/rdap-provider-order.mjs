import assert from 'node:assert/strict';
import { lookupRdapDomain, normalizeRdapResponse } from '../src/analyzer/domain/rdap-features.js';

const payload={status:'success',domain:'example.org',data:{domainName:'EXAMPLE.ORG',creationDate:'2004-01-30T00:08:43Z',nameServers:['ns1.example.org'],rawRdap:{ldhName:'EXAMPLE.ORG',events:[{eventAction:'registration',eventDate:'2004-01-30T00:08:43Z'}],nameservers:[{ldhName:'ns1.example.org'}]}}};
assert.ok(normalizeRdapResponse(payload).domain_age_days>7000);
assert.equal(normalizeRdapResponse(payload).nameserver_count,1);
const original=globalThis.fetch;
let calls=[];
try {
  globalThis.fetch=async url=>{calls.push(url);return {ok:true,json:async()=>payload};};
  const result=await lookupRdapDomain('example.org');
  assert.equal(result.rdap_available,true);
  assert.deepEqual(calls,['https://api-check-beryl-beta.vercel.app/api/whois?domain=example.org']);
  calls=[];
  globalThis.fetch=async url=>{
    calls.push(url);
    if(calls.length===1) throw new Error('offline');
    if(calls.length===2) return {ok:false,status:503};
    return {ok:true,json:async()=>calls.length===3?{status:'error'}:payload};
  };
  assert.equal((await lookupRdapDomain('example.org')).rdap_available,true);
  assert.deepEqual(calls,[
    'https://api-check-beryl-beta.vercel.app/api/whois?domain=example.org',
    'http://localhost:3000/api/whois?domain=example.org',
    'https://whois-api-dun.vercel.app/api/whois?domain=example.org',
    'https://who-dat.as93.net/example.org'
  ]);
  calls=[];
  globalThis.fetch=async (url,{signal})=>{
    calls.push(url);
    if(calls.length>1) return {ok:true,json:async()=>payload};
    return {ok:true,json:()=>new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(new DOMException('timeout','AbortError')),{once:true}))};
  };
  assert.equal((await lookupRdapDomain('example.org',{timeoutMs:20})).rdap_available,true);
  assert.equal(calls.length,2);
  calls=[];
  globalThis.fetch=async url=>{calls.push(url);return {ok:false,status:404};};
  assert.equal((await lookupRdapDomain('example.org')).rdap_available,false);
  assert.equal(calls.length,4);
} finally {globalThis.fetch=original;}
console.log('rdap-provider-order: PASS (Beryl first, ordered fallbacks, nested raw RDAP, body timeout, unavailable result).');
