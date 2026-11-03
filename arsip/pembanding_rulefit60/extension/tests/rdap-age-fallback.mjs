import assert from "node:assert/strict";
import { lookupRdapDomain } from "../src/analyzer/domain/rdap-features.js";

const originalFetch = globalThis.fetch;
const base = "https://api.example/{domain}";
const fallback = "https://api.backup/{domain}";
try {
  const calls = [];
  globalThis.fetch = async url => {
    calls.push(url);
    return { ok: true, json: async () => calls.length === 1
      ? { domain: "example.org", nameservers: ["ns.example.org"] }
      : { domain: "example.org", creationDate: "2020-01-01T00:00:00Z" } };
  };
  const recovered = await lookupRdapDomain("example.org", { apiUrls: [base, fallback] });
  assert.ok(recovered.domain_age_days > 0);
  assert.equal(calls.length, 2, "metadata without creation date must not stop fallback");

  globalThis.fetch = async () => ({ ok: true, json: async () =>
    ({ domain: "example.org", nameservers: ["ns.example.org"] }) });
  const missing = await lookupRdapDomain("example.org", { apiUrls: [base, fallback] });
  assert.equal(missing.domain_age_days, null);
  assert.match(missing.rdap_error, /missing_registration_date/);

  let count = 0;
  globalThis.fetch = async () => ({ ok: true, json: async () => ++count === 1
    ? { domain: "other.org", creationDate: "2000-01-01T00:00:00Z" }
    : { domain: "example.org", creationDate: "2020-01-01T00:00:00Z" } });
  assert.ok((await lookupRdapDomain("example.org", { apiUrls: [base, fallback] })).domain_age_days > 0);
  assert.equal(count, 2, "a date for another domain must be rejected");
} finally {
  globalThis.fetch = originalFetch;
}
console.log("PASS RDAP age fallback and missing-date handling");
