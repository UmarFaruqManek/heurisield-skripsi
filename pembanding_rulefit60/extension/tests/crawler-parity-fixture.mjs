import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { extractBrandFeatureSet } from "../src/analyzer/brand/brand-features.js";
import { extractDomFeaturesFromDocument } from "../src/analyzer/dom/dom-features.js";
import { extractRdapFeatureSet, normalizeRdapResponse } from "../src/analyzer/domain/rdap-features.js";
import { extractCrawlerUrlFeatureSet, flattenSensitiveKeywordConfig } from "../src/analyzer/url/url-features.js";
import { buildFeatureVector, summarizeFeatureCoverage } from "../src/analyzer/feature-assembler.js";
import { normalizeFeatureRecord } from "../src/rule/feature-names.js";

const originalUrl = "https://login.bankexample.com/account?next=https%3A%2F%2Fevil.com%2Fcollect&token=REDACTED";
const finalUrl = "https://login.bankexample.com/account?next=https%3A%2F%2Fevil.com%2Fcollect&token=REDACTED";
const html = `
<!doctype html>
<html>
  <head>
    <title>Bankexample - Secure Login</title>
    <meta http-equiv="refresh" content="0; url=https://login.bankexample.com/next">
    <link rel="stylesheet" href="https://cdn.example/app.css">
  </head>
  <body>
    <form method="post" action="https://login.bankexample.com/collect">
      <input type="email" name="email">
      <input type="password" name="password">
      <input type="hidden" name="csrf">
    </form>
    <a href="/help">Help</a>
    <a href="https://external.com/about">External</a>
    <img src="https://cdn.com/logo.png">
    <script>eval('x'); document.write('x'); window.open('/x')</script>
    <script src="https://cdn.com/app.js"></script>
    <iframe src="https://login.bankexample.com/frame"></iframe>
  </body>
</html>`;
const rdapPayload = {
  data: {
    domainName: "bankexample.com",
    creationDate: "2010-01-01T00:00:00Z",
    expirationDate: "2030-01-01T00:00:00Z",
    updatedDate: "2025-01-01T00:00:00Z",
    nameServers: ["ns1.bankexample.com", "ns2.bankexample.com"]
  }
};
const brandLookupResult = {
  source: "final_title",
  query: "bankexample",
  lookup_success: true,
  top_results: [
    { name: "Bankexample", domain: "bankexample.com", _score: 101, qualityScore: 0.93 }
  ]
};

const crawlerPythonPath = resolveCrawlerPythonPath();
const featureContract = JSON.parse(await readFile(new URL("./fixtures/feature-contract-30.json", import.meta.url), "utf8"));
const sensitiveConfig = JSON.parse(await readFile(new URL("../src/analyzer/sensitive-url-keywords.json", import.meta.url), "utf8"));
const sensitiveKeywords = flattenSensitiveKeywordConfig(sensitiveConfig);

const crawler = JSON.parse(execFileSync("python", ["-c", `
import json
from heurishield_crawler.url_features import extract_url_features, calculate_redirect_fields
from heurishield_crawler.schema import prefixed_url_features, prefix_rdap, top_brand_candidate
from heurishield_crawler.rdap import normalize_rdap_response
from heurishield_crawler.dom_analyzer import analyze_dom

original_url = ${JSON.stringify(originalUrl)}
final_url = ${JSON.stringify(finalUrl)}
html = ${JSON.stringify(html)}
sensitive_keywords = json.loads(${JSON.stringify(JSON.stringify(sensitiveKeywords))})
rdap_payload = json.loads(${JSON.stringify(JSON.stringify(rdapPayload))})
brand_result = json.loads(${JSON.stringify(JSON.stringify(brandLookupResult))})
credential_keywords = {
  "username": ["user", "username", "userid", "login", "account", "member", "customer"],
  "email": ["email", "e-mail", "mail"],
  "password": ["password", "passwd", "passcode", "pwd", "kata sandi"],
  "otp_mfa": ["otp", "mfa", "2fa", "verification code", "security code", "one time", "kode verifikasi"],
  "pin": ["pin", "mpin"],
  "payment_card": ["card", "credit", "debit", "cc", "cvv", "cvc", "expiry", "expiration", "cardnumber"],
  "identity_personal": ["identity", "id number", "ssn", "passport", "ktp", "nik", "dob", "birth"],
}
url = {}
url.update(prefixed_url_features(original_url, "original", sensitive_keywords))
url.update(prefixed_url_features(final_url, "final", sensitive_keywords))
url.update(extract_url_features(final_url, sensitive_keywords))
url.update(calculate_redirect_fields(original_url, final_url, []))
dom = analyze_dom(html, final_url, credential_keywords)
rdap = {}
rdap.update(prefix_rdap(normalize_rdap_response(rdap_payload), "original"))
rdap.update(prefix_rdap(normalize_rdap_response(rdap_payload), "final"))
brand = top_brand_candidate([brand_result], original_url, final_url)
brand["brand_lookup_success"] = any(item.get("lookup_success") for item in [brand_result])
print(json.dumps({"url": url, "dom": dom, "rdap": rdap, "brand": brand}, sort_keys=True))
`], {
  cwd: new URL("../../", import.meta.url),
  encoding: "utf8",
  env: {
    ...process.env,
    PYTHONPATH: [crawlerPythonPath, process.env.PYTHONPATH].filter(Boolean).join(process.platform === "win32" ? ";" : ":")
  }
}));

const jsUrl = extractCrawlerUrlFeatureSet({ originalUrl, finalUrl, sensitiveKeywords });
const jsDom = extractDomFeaturesFromDocument(makeFakeDocument(), finalUrl, { html });
const jsRdap = await extractRdapFeatureSet({
  originalDomain: "bankexample.com",
  finalDomain: "bankexample.com",
  lookup: async () => normalizeRdapResponse(rdapPayload)
});
const jsBrand = await extractBrandFeatureSet({
  originalUrl,
  finalUrl,
  title: "Bankexample - Secure Login",
  lookup: async (query) => ({
    query,
    lookup_success: true,
    candidates: query === "bankexample"
      ? [{ name: "Bankexample", domain: "bankexample.com", source: "final_title", _score: 101, qualityScore: 0.93 }]
      : []
  })
});
const status = { http_status_code: 200 };
const combined = buildFeatureVector(featureContract.features, {
  url: jsUrl,
  dom: jsDom,
  rdap: jsRdap,
  brand: jsBrand,
  status
});

const keysToCompare = [
  "url_length", "hostname_length", "path_length", "query_length", "query_parameter_count",
  "dot_count", "hyphen_count", "digit_count", "embedded_domain_count", "sensitive_word_count",
  "source_url_length", "page_url_length", "redirect_count",
  "html_length", "dom_node_count", "input_count", "password_input_count", "credential_form_count",
  "anchor_count", "external_anchor_count", "resource_count", "script_count", "eval_count",
  "original_nameserver_count", "final_nameserver_count", "original_rdap_available", "final_rdap_available",
  "brand_found", "brand_matches_source", "brand_matches_page",
  "brand_search_score", "brand_quality_score", "brand_lookup_success"
];

const jsAll = { ...jsUrl, ...jsDom, ...jsRdap, ...jsBrand, ...status };
const crawlerAll = normalizeFeatureRecord({ ...crawler.url, ...crawler.dom, ...crawler.rdap, ...crawler.brand, ...status });
const mismatches = [];
for (const key of keysToCompare) {
  if (!approximatelyEqual(jsAll[key], crawlerAll[key])) {
    mismatches.push({ key, js: jsAll[key], crawler: crawlerAll[key] });
  }
}

assert.deepEqual(mismatches, []);
assert.equal(combined.missing_features.length, 0);

console.log("crawler-parity-fixture: PASS");
console.log(JSON.stringify({
  compared_features: keysToCompare.length,
  full_mocked_runtime: summarizeFeatureCoverage(combined)
}, null, 2));

function approximatelyEqual(left, right) {
  if (typeof left === "boolean") left = left ? 1 : 0;
  if (typeof right === "boolean") right = right ? 1 : 0;
  if (typeof left === "number" && typeof right === "number") return Math.abs(left - right) < 1e-9;
  return left === right;
}

function resolveCrawlerPythonPath() {
  const candidates = [
    new URL("file:///D:/mesin%20crawl/_backup_root_cleanup_20261011/folders/"),
    new URL("../../", import.meta.url),
    new URL("../../_backup_root_cleanup_20261011/folders/", import.meta.url)
  ];
  for (const candidate of candidates) {
    const path = fileURLToPath(candidate);
    if (existsSync(fileURLToPath(new URL("heurishield_crawler", candidate)))) return path;
  }
  return fileURLToPath(new URL("../../", import.meta.url));
}

function makeFakeDocument() {
  const title = fakeElement({}, { tagName: "TITLE", textContent: "Bankexample - Secure Login" });
  const meta = fakeElement({ "http-equiv": "refresh", content: "0; url=https://login.bankexample.com/next" }, { tagName: "META" });
  const formInputs = [
    fakeElement({ type: "email", name: "email" }),
    fakeElement({ type: "password", name: "password" }),
    fakeElement({ type: "hidden", name: "csrf" })
  ];
  const form = fakeContainer({ method: "post", action: "https://login.bankexample.com/collect" }, formInputs);
  const anchors = [
    fakeElement({ href: "/help" }, { tagName: "A" }),
    fakeElement({ href: "https://external.com/about" }, { tagName: "A" })
  ];
  const scripts = [
    fakeElement({}, { tagName: "SCRIPT", textContent: "eval('x'); document.write('x'); window.open('/x')" }),
    fakeElement({ src: "https://cdn.com/app.js" }, { tagName: "SCRIPT" })
  ];
  const stylesheets = [fakeElement({ rel: "stylesheet", href: "https://cdn.com/app.css" }, { tagName: "LINK" })];
  const images = [fakeElement({ src: "https://cdn.com/logo.png" }, { tagName: "IMG" })];
  const iframes = [fakeElement({ src: "https://login.bankexample.com/frame" }, { tagName: "IFRAME" })];
  const htmlNode = fakeElement({}, { tagName: "HTML" });
  const headNode = fakeElement({}, { tagName: "HEAD" });
  const bodyNode = fakeElement({}, { tagName: "BODY" });
  const all = [htmlNode, headNode, title, meta, ...stylesheets, bodyNode, form, ...formInputs, ...anchors, ...images, ...scripts, ...iframes];
  const bodyText = "Bankexample Secure Login Help External";
  return {
    location: { href: finalUrl },
    documentElement: { outerHTML: html },
    body: {
      textContent: bodyText,
      cloneNode() {
        return { textContent: bodyText, querySelectorAll: () => [], remove() {} };
      }
    },
    querySelector(selector) {
      if (selector === "title") return title;
      if (selector.startsWith("base")) return null;
      return null;
    },
    querySelectorAll(selector) {
      if (selector === "*") return all;
      if (selector === "input, textarea, select") return formInputs;
      if (selector === "form") return [form];
      if (selector === "iframe") return iframes;
      if (selector === "a") return anchors;
      if (selector === "img") return images;
      if (selector === "script") return scripts;
      if (selector === "link[rel~='stylesheet']") return stylesheets;
      if (selector === "meta[http-equiv]") return [meta];
      return [];
    }
  };
}

function fakeElement(attrs = {}, options = {}) {
  return {
    tagName: options.tagName || "INPUT",
    textContent: options.textContent || "",
    ownerDocument: null,
    getAttribute(name) {
      return attrs[name] ?? attrs[name.toLowerCase()] ?? "";
    },
    closest() {
      return null;
    },
    querySelectorAll() {
      return [];
    },
    cloneNode() {
      return this;
    },
    remove() {}
  };
}

function fakeContainer(attrs, children) {
  return {
    ...fakeElement(attrs, { tagName: "FORM" }),
    querySelectorAll(selector) {
      return selector === "input, textarea, select" ? children : [];
    }
  };
}
