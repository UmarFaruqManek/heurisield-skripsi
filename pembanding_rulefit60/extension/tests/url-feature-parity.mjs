import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  calculateRedirectFields,
  extractCrawlerUrlFeatureSet,
  extractUrlFeatures,
  flattenSensitiveKeywordConfig
} from "../src/analyzer/url/url-features.js";
import { buildFeatureVector, summarizeFeatureCoverage } from "../src/analyzer/feature-assembler.js";
import { evaluateRuleFitEngine } from "../src/rule/rulefit-engine.js";

const sensitiveConfig = JSON.parse(await readFile(new URL("../src/analyzer/sensitive-url-keywords.json", import.meta.url), "utf8"));
// Fixture historis untuk tes regresi; extension memakai engine 60 fitur di src/rule.
const featureContract = JSON.parse(await readFile(new URL("./fixtures/feature-contract-30.json", import.meta.url), "utf8"));
const rulefitEngine = JSON.parse(await readFile(new URL("./fixtures/rulefit-engine-30.json", import.meta.url), "utf8"));
const sensitiveKeywords = flattenSensitiveKeywordConfig(sensitiveConfig);

const url = "https://login-example-paypal.com/account/verify?session=REDACTED&next=https%3A%2F%2Fpaypal.com";
const features = extractUrlFeatures(url, sensitiveKeywords);

assert.equal(features.scheme, "https");
assert.equal(features.hostname, "login-example-paypal.com");
assert.equal(features.registrable_domain, "login-example-paypal.com");
assert.equal(features.path_length, "/account/verify".length);
assert.equal(features.query_parameter_count, 2);
assert.equal(features.encoded_char_count, 3);
assert.equal(features.sensitive_word_count >= 2, true);
assert.equal(features.url_token_count > 0, true);

const redirects = calculateRedirectFields(
  "https://abc.com",
  "https://paypal.com",
  ["https://abc.com", "https://xyz.com", "https://paypal.com"]
);
assert.deepEqual(redirects.redirect_chain, ["https://abc.com", "https://xyz.com", "https://paypal.com"]);
assert.equal(redirects.cross_domain_redirect_count, 2);
assert.equal(redirects.final_domain_changed, true);

const sameDomain = calculateRedirectFields(
  "https://example.com",
  "https://example.com/login",
  ["https://example.com", "https://example.com/login"]
);
assert.equal(sameDomain.cross_domain_redirect_count, 0);

const crawlerSet = extractCrawlerUrlFeatureSet({
  originalUrl: "https://abc.com/login",
  finalUrl: url,
  redirectChain: ["https://abc.com/login", url],
  sensitiveKeywords
});
const assembled = buildFeatureVector(featureContract.features, { url: crawlerSet });
const coverage = summarizeFeatureCoverage(assembled);
assert.equal(assembled.feature_count, 30);
assert.equal(assembled.vector.source_path_length, "/login".length);
assert.equal(assembled.vector.page_url_entropy > 0, true);
assert.equal(coverage.provided_features >= 14, true);

const decision = evaluateRuleFitEngine(rulefitEngine, assembled.vector);
assert.equal(decision.ready, true);
assert.equal(["phishing", "legitimate"].includes(decision.predicted_label), true);
assert.equal(Array.isArray(decision.fired_rules), true);

console.log("url-feature-parity: PASS");
console.log(JSON.stringify({
  feature_count: assembled.feature_count,
  provided_features: assembled.provided_features,
  missing_features: assembled.missing_features.length,
  decision: {
    predicted_label: decision.predicted_label,
    probability_phishing: decision.probability_phishing,
    fired_rule_count: decision.fired_rule_count
  }
}, null, 2));

