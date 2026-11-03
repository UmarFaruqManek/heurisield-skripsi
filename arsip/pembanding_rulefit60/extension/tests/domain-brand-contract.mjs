import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { buildBrandQueries, extractBrandFeatureSet } from "../src/analyzer/brand/brand-features.js";
import { extractRdapFeatureSet, normalizeRdapResponse } from "../src/analyzer/domain/rdap-features.js";
import { extractCrawlerUrlFeatureSet, flattenSensitiveKeywordConfig } from "../src/analyzer/url/url-features.js";
import { extractDomFeaturesFromDocument } from "../src/analyzer/dom/dom-features.js";
import { buildFeatureVector, summarizeFeatureCoverage } from "../src/analyzer/feature-assembler.js";
import { buildRuntimeFeatureAnalysis } from "../src/analyzer/runtime-analysis.js";

const featureContract = JSON.parse(await readFile(new URL("./fixtures/feature-contract-30.json", import.meta.url), "utf8"));
const sensitiveConfig = JSON.parse(await readFile(new URL("../src/analyzer/sensitive-url-keywords.json", import.meta.url), "utf8"));
const sensitiveKeywords = flattenSensitiveKeywordConfig(sensitiveConfig);

const rdap = normalizeRdapResponse({
  data: {
    domainName: "bank.example",
    creationDate: "2010-01-01T00:00:00Z",
    expirationDate: "2030-01-01T00:00:00Z",
    updatedDate: "2025-01-01T00:00:00Z",
    nameServers: ["ns1.bank.example", "ns2.bank.example"]
  }
});
assert.equal(rdap.rdap_available, true);
assert.equal(rdap.nameserver_count, 2);
assert.equal(rdap.registration_lifetime_days, 7305);

const idRdap = normalizeRdapResponse({
  domain: "kizukuacademy.id",
  dates: {
    created: "2026-06-19T12:09:02Z",
    updated: "2026-07-06T11:21:29Z",
    expires: "2027-06-19T23:59:59Z"
  },
  nameservers: [
    { name: "ns1.dns-parking.com" },
    { name: "ns2.dns-parking.com" }
  ]
});
assert.equal(idRdap.rdap_available, true);
assert.equal(idRdap.nameserver_count, 2);
assert.equal(idRdap.registration_lifetime_days, 365);

const rdapFeatures = await extractRdapFeatureSet({
  originalDomain: "bank.example",
  finalDomain: "bank.example",
  lookup: async () => rdap
});
assert.equal(rdapFeatures.original_rdap_available, true);
assert.equal(rdapFeatures.final_nameserver_count, 2);

const brandFeatures = await extractBrandFeatureSet({
  originalUrl: "https://login.bank.example/login",
  finalUrl: "https://login.bank.example/login",
  title: "Bank Example - Secure Login",
  lookup: async (query) => ({
    query,
    lookup_success: true,
    candidates: query.includes("bank")
      ? [{ name: "Bank Example", domain: "bank.example", source: "brandfetch", _score: 101, qualityScore: 0.93 }]
      : []
  })
});
assert.equal(brandFeatures.brand_found, true);
assert.equal(brandFeatures.brand_matches_page, true);
assert.equal(brandFeatures.brand_lookup_success, true);

const educationBrandQueries = buildBrandQueries(
  "LPK Kizuku International Academy - Wujudkan Karier Impian di Jepang",
  "kizukuacademy.id",
  "kizukuacademy.id"
);
assert.equal(educationBrandQueries.includes("academy"), false);
assert.equal(educationBrandQueries.includes("international"), false);
assert.equal(educationBrandQueries.includes("kizukuacademy"), true);

const regionalBrandQueries = buildBrandQueries("", "shopee.co.id", "shopee.co.id");
assert.equal(regionalBrandQueries.includes("shopee"), true);
assert.equal(regionalBrandQueries.includes("co"), false);

const academicBrandQueries = buildBrandQueries("", "simak.uho.ac.id", "simak.uho.ac.id");
assert.equal(academicBrandQueries.includes("uho"), true);
assert.equal(academicBrandQueries.includes("ac"), false);

const educationBrandFeatures = await extractBrandFeatureSet({
  originalUrl: "https://kizukuacademy.id/",
  finalUrl: "https://kizukuacademy.id/",
  title: "LPK Kizuku International Academy - Wujudkan Karier Impian di Jepang",
  lookup: async (query) => ({
    query,
    lookup_success: true,
    candidates: query === "academy"
      ? [{ name: "Academy Sports + Outdoors", domain: "academy.com", source: "brandfetch", _score: 60, qualityScore: 0.96 }]
      : query === "kizukuacademy"
        ? [{ name: "Kizuku Co.", domain: "kizuku.co", source: "brandfetch", _score: 38, qualityScore: 0.41 }]
        : []
  })
});
assert.equal(educationBrandFeatures.brand_found, false);
assert.equal(educationBrandFeatures.brand_top_candidate_source, null);
assert.equal(educationBrandFeatures.brand_top_candidate_domain, null);
assert.equal(educationBrandFeatures.brand_matches_page, false);

const invalidBrandDomainFeatures = await extractBrandFeatureSet({
  originalUrl: "https://claude.com/programs/startups",
  finalUrl: "https://claude.com/programs/startups",
  title: "Claude for Startups",
  lookup: async (query) => ({
    query,
    lookup_success: true,
    candidates: query === "claude"
      ? [{ name: "Claude", domain: "claude", source: "brandfetch", _score: 80, qualityScore: 0.97 }]
      : []
  })
});
assert.equal(invalidBrandDomainFeatures.brand_found, false);
assert.equal(invalidBrandDomainFeatures.brand_top_candidate_source, null);
assert.equal(invalidBrandDomainFeatures.brand_top_candidate_domain, null);
assert.equal(invalidBrandDomainFeatures.brand_matches_page, false);

const dicodingBrandFeatures = await extractBrandFeatureSet({
  originalUrl: "https://www.dicoding.com/",
  finalUrl: "https://www.dicoding.com/",
  title: "Dicoding Indonesia",
  lookup: async (query) => ({
    query,
    lookup_success: true,
    candidates: query === "dicoding"
      ? [{ name: "dicoding", domain: "dicoding", source: "brandfetch", _score: 80, qualityScore: 0.97 }]
      : []
  })
});
assert.equal(dicodingBrandFeatures.brand_found, false);
assert.equal(dicodingBrandFeatures.brand_top_candidate_source, null);
assert.equal(dicodingBrandFeatures.brand_top_candidate_domain, null);
assert.equal(dicodingBrandFeatures.brand_matches_page, false);

const validExternalBrandFeatures = await extractBrandFeatureSet({
  originalUrl: "https://www.dicoding.com/",
  finalUrl: "https://www.dicoding.com/",
  title: "Dicoding Indonesia",
  lookup: async (query) => ({
    query,
    lookup_success: true,
    candidates: query === "dicoding"
      ? [{ name: "dicoding", domain: "dicoding.com", source: "brandfetch", _score: 80, qualityScore: 0.97 }]
      : []
  })
});
assert.equal(validExternalBrandFeatures.brand_found, true);
assert.equal(validExternalBrandFeatures.brand_top_candidate_domain, "dicoding.com");
assert.equal(validExternalBrandFeatures.brand_matches_page, true);

const regionalRuntime = await buildRuntimeFeatureAnalysis({
  originalUrl: "https://shopee.co.id/",
  finalUrl: "https://shopee.co.id/",
  title: "Shopee Indonesia",
  domFeatures: { external_credential_form_count: 0, ip_credential_form_count: 0 },
  featureContract,
  rulefitEngine: {
    model_family: "RuleFit",
    threshold: 0.8,
    intercept: 5,
    imputer_median: {},
    rules: []
  },
  sensitiveKeywords,
  rdapLookup: async () => normalizeRdapResponse({
    domain: "shopee.co.id",
    creationDate: "2015-01-01T00:00:00Z",
    expirationDate: "2030-01-01T00:00:00Z",
    nameServers: ["ns1.example", "ns2.example"]
  }),
  brandLookup: async (query) => ({
    query,
    lookup_success: true,
    candidates: query === "shopee"
      ? [{ name: "Shopee Brasil", domain: "shopee.com.br", source: "brandfetch", _score: 86, qualityScore: 0.88 }]
      : []
  })
});
assert.equal(regionalRuntime.brand_features.brand_top_candidate_domain, "shopee.com.br");
assert.equal(regionalRuntime.model_result.predicted_label, "legitimate");
assert.equal(regionalRuntime.model_result.post_model_guard.id, "SELF_BRAND_LABEL_GUARD");

const urlFeatures = extractCrawlerUrlFeatureSet({
  originalUrl: "https://login.bank.example/login",
  finalUrl: "https://login.bank.example/login",
  sensitiveKeywords
});
const domFeatures = extractDomFeaturesFromDocument(makeFakeDocument(), "https://login.bank.example/login", {
  html: "<html><body>login account</body></html>"
});
const statusFeatures = { http_status_code: 200 };
const combined = buildFeatureVector(featureContract.features, {
  url: urlFeatures,
  dom: domFeatures,
  rdap: rdapFeatures,
  brand: brandFeatures,
  status: statusFeatures
});

assert.equal(combined.feature_count, 30);
assert.equal(combined.missing_features.length, 0);

console.log("domain-brand-contract: PASS");
console.log(JSON.stringify({
  full_mocked_runtime: summarizeFeatureCoverage(combined)
}, null, 2));

function makeFakeDocument() {
  const bodyText = "Bank Example secure login account";
  return {
    location: { href: "https://login.bank.example/login" },
    documentElement: { outerHTML: "<html></html>" },
    body: {
      textContent: bodyText,
      cloneNode() {
        return {
          textContent: bodyText,
          querySelectorAll() {
            return [];
          }
        };
      }
    },
    querySelector() {
      return null;
    },
    querySelectorAll(selector) {
      if (selector === "*") return [];
      return [];
    }
  };
}
