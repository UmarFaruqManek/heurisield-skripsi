import assert from 'node:assert/strict';
import {createBrandLookupCache} from '../src/analyzer/brand/brand-lookup-cache.js';
let storage={}; let calls=0; let clock=100000;
let response={query:'roblox',lookup_success:true,candidates:[{name:'Roblox',domain:'roblox.com'}]};
const lookup=createBrandLookupCache({
  lookup:async()=>{calls++;await new Promise(r=>setTimeout(r,10));return response;},
  getCache:async()=>structuredClone(storage),
  updateCache:async mutate=>mutate(storage),
  now:()=>clock,ttlMs:86400000,emptyTtlMs:60000
});
await Promise.all([lookup('roblox'),lookup('ROBLOX')]);
assert.equal(calls,1,'Concurrent requests must share one API call');
await lookup('roblox');assert.equal(calls,1);
await lookup('roblox',{forceRefresh:true});assert.equal(calls,2);
response={query:'roblox',lookup_success:false,candidates:[]};
await lookup('roblox',{forceRefresh:true});
assert.equal(Object.keys(storage).length,0,'Do not retain transient API failures');
response={query:'roblox',lookup_success:true,candidates:[{name:'Roblox',domain:'roblox.com'}]};
assert.equal((await lookup('roblox')).candidates[0].name,'Roblox');assert.equal(calls,4);
response={query:'unknown',lookup_success:true,candidates:[]};
await lookup('unknown');const before=calls;
clock+=59999;await lookup('unknown');assert.equal(calls,before);
clock+=2;await lookup('unknown');assert.equal(calls,before+1,'Empty results expire quickly');
const key='brand:clearbit-first:v5:failed';
storage[key]={metadata:{lookup_success:false,candidates:[]},cached_at:new Date(clock).toISOString()};
response={query:'failed',lookup_success:true,candidates:[{name:'Recovered',domain:'recovered.example'}]};
assert.equal((await lookup('failed')).candidates[0].name,'Recovered','Ignore older cached failures');
console.log('brand-lookup-cache: PASS (deduplication, force refresh, recovery, short negative cache)');
