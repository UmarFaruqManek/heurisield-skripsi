import assert from "node:assert/strict";
import { hostnameBrandParts, hostnameBrandQueries } from "../src/shared/brand-claim-guard.js";

const cases = [
  ["kkn.uho.ac.id", "ac.id", "uho.ac.id", "kkn", ["kkn", "uho"]],
  ["app.dicoding.com", "com", "dicoding.com", "app", ["app", "dicoding"]],
  ["roblox.com.py", "com.py", "roblox.com.py", "", ["roblox"]],
  ["abc.pages.dev", "pages.dev", "abc.pages.dev", "", ["abc"]],
  ["rohith1307.github.io", "github.io", "rohith1307.github.io", "", ["rohith1307"]]
];

for (const [host, suffix, domain, subdomain, queries] of cases) {
  const parts = hostnameBrandParts(host);
  assert.equal(parts.publicSuffix, suffix, host);
  assert.equal(parts.registrableDomain, domain, host);
  assert.equal(parts.subdomain, subdomain, host);
  assert.deepEqual(hostnameBrandQueries(host), queries, host);
}
console.log("PASS public suffix and brand query boundaries");
