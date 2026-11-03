import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  classifyCredentialInput,
  classifyDestination,
  DOM_FEATURE_VERSION,
  extractDomFeaturesFromDocument
} from "../src/analyzer/dom/dom-features.js";
import { extractCrawlerUrlFeatureSet, flattenSensitiveKeywordConfig } from "../src/analyzer/url/url-features.js";
import { buildFeatureVector, summarizeFeatureCoverage } from "../src/analyzer/feature-assembler.js";

const featureContract = JSON.parse(await readFile(new URL("./fixtures/feature-contract-30.json", import.meta.url), "utf8"));
const sensitiveConfig = JSON.parse(await readFile(new URL("../src/analyzer/sensitive-url-keywords.json", import.meta.url), "utf8"));
const sensitiveKeywords = flattenSensitiveKeywordConfig(sensitiveConfig);

const external = classifyDestination(
  "https://evil.example/login",
  "https://bank.example/account",
  "bank.example"
);
assert.equal(external.type, "external_domain");
assert.equal(external.domain, "evil.example");

const same = classifyDestination("/signin", "https://bank.example/account", "bank.example");
assert.equal(same.type, "same_domain");
assert.equal(same.domain, "bank.example");

const ip = classifyDestination("http://192.168.0.12/post", "https://bank.example", "bank.example");
assert.equal(ip.type, "ip");

const passwordInput = fakeElement({
  type: "password",
  name: "login_password",
  id: "pwd"
});
assert.equal(classifyCredentialInput(passwordInput).includes("password"), true);

const otpInput = fakeElement({
  type: "text",
  name: "security_code",
  placeholder: "OTP code"
});
assert.equal(classifyCredentialInput(otpInput).includes("otp_mfa"), true);

const fakeDoc = makeFakeDocument({
  title: fakeText("Secure Login"),
  metas: [fakeElement({ "http-equiv": "refresh", content: "0; url=https://evil.example/next" })],
  bases: [fakeElement({ href: "https://bank.example/" })],
  inputs: [
    fakeElement({ type: "email", name: "email" }),
    fakeElement({ type: "password", name: "password" }),
    fakeElement({ type: "hidden", name: "csrf" })
  ],
  forms: [
    fakeContainer({ method: "post", action: "https://evil.example/collect" }, [
      fakeElement({ type: "email", name: "email" }),
      fakeElement({ type: "password", name: "password" })
    ])
  ],
  anchors: [
    fakeElement({ href: "/help" }),
    fakeElement({ href: "https://cdn.example/assets" }),
    fakeElement({ href: "javascript:void(0)" })
  ],
  images: [fakeElement({ src: "https://cdn.example/logo.png" })],
  scripts: [
    fakeText("eval('x'); document.write('x'); window.open('/x')"),
    fakeElement({ src: "https://cdn.example/app.js" })
  ],
  stylesheets: [fakeElement({ href: "https://cdn.example/app.css", rel: "stylesheet" })],
  iframes: [fakeElement({ src: "https://evil.example/frame" })]
});

const domFeatures = extractDomFeaturesFromDocument(fakeDoc, "https://bank.example/login", {
  html: "<html><body>secure login</body></html>"
});

assert.equal(domFeatures.analyzer_version, DOM_FEATURE_VERSION);
assert.equal(domFeatures.input_count, 3);
assert.equal(domFeatures.password_input_count, 1);
assert.equal(domFeatures.credential_form_count, 1);
assert.equal(domFeatures.external_credential_form_count, 1);
assert.equal(domFeatures.external_anchor_count, 1);
assert.equal(domFeatures.javascript_anchor_count, 1);
assert.equal(domFeatures.eval_count, 1);
assert.equal(domFeatures.document_write_count, 1);
assert.equal(domFeatures.window_open_count, 1);
assert.equal(domFeatures.meta_refresh_external, true);
assert.equal(domFeatures.external_resource_count, 4);

const urlFeatures = extractCrawlerUrlFeatureSet({
  originalUrl: "https://bank.example/login",
  finalUrl: "https://bank.example/login",
  redirectChain: [],
  sensitiveKeywords
});
const urlOnly = buildFeatureVector(featureContract.features, { url: urlFeatures });
const combined = buildFeatureVector(featureContract.features, { url: urlFeatures, dom: domFeatures });

assert.equal(combined.feature_count, 30);
assert.equal(combined.provided_features > urlOnly.provided_features, true);
assert.equal(combined.vector.resource_count, 5);
assert.equal(combined.vector.external_anchor_count, 1);

console.log("dom-feature-contract: PASS");
console.log(JSON.stringify({
  url_only: summarizeFeatureCoverage(urlOnly),
  url_dom_combined: summarizeFeatureCoverage(combined)
}, null, 2));

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

function fakeText(text) {
  return fakeElement({}, { textContent: text, tagName: "SCRIPT" });
}

function fakeContainer(attrs, children) {
  return {
    ...fakeElement(attrs, { tagName: "FORM" }),
    querySelectorAll(selector) {
      return selector === "input, textarea, select" ? children : [];
    }
  };
}

function makeFakeDocument(parts) {
  const allElements = [
    ...(parts.inputs || []),
    ...(parts.forms || []),
    ...(parts.anchors || []),
    ...(parts.images || []),
    ...(parts.scripts || []),
    ...(parts.stylesheets || []),
    ...(parts.iframes || []),
    ...(parts.metas || []),
    ...(parts.bases || [])
  ];
  const bodyText = "Secure login account password";
  return {
    location: { href: "https://bank.example/login" },
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
    querySelector(selector) {
      if (selector === "title") return parts.title || null;
      if (selector.startsWith("base")) return parts.bases?.[0] || null;
      if (selector.startsWith("meta")) return null;
      return null;
    },
    querySelectorAll(selector) {
      if (selector === "*") return allElements;
      if (selector === "input, textarea, select") return parts.inputs || [];
      if (selector === "form") return parts.forms || [];
      if (selector === "iframe") return parts.iframes || [];
      if (selector === "a") return parts.anchors || [];
      if (selector === "img") return parts.images || [];
      if (selector === "script") return parts.scripts || [];
      if (selector === "link[rel~='stylesheet']") return parts.stylesheets || [];
      if (selector === "meta[http-equiv]") return parts.metas || [];
      return [];
    }
  };
}
