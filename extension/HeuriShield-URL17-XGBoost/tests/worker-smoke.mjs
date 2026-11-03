/* Offline worker smoke: fake registration API and extension storage, no web visit. */
import fs from "node:fs/promises";

const storage = new Map();
let listener;
let beforeNavigate;
let currentTabUrl = "https://account.example.com/login";
const on = { addListener(fn) { if (fn.length === 3) listener = fn; } };
const base = new URL("../", import.meta.url);
globalThis.chrome = {
  runtime: {
    id: "test-extension", getURL: path => new URL(path, base).href,
    onInstalled: on, onMessage: on
  },
  storage: { local: {
    async get(keys) {
      if (typeof keys === "string") return { [keys]: storage.get(keys) };
      if (Array.isArray(keys)) return Object.fromEntries(keys.map(key => [key, storage.get(key)]));
      return Object.fromEntries(Object.entries(keys).map(([key, fallback]) => [key, storage.has(key) ? storage.get(key) : fallback]));
    },
    async set(values) { for (const [key, value] of Object.entries(values)) storage.set(key, value); }
  } },
  tabs: {
    async get() { return { url: currentTabUrl }; },
    async update(tabId, changes) { currentTabUrl = changes.url; return { id: tabId, url: currentTabUrl }; },
    async sendMessage(tabId, message) {
      if (message.type !== "HEURISHIELD_COLLECT_EVIDENCE") return { ok: true };
      if (tabId === 5) return { ok: true, snapshot: {
        page_origin: "https://portal.merdekasiber.com", title: "Merdeka Siber Private Labs",
        headings: [{ text: "Merdeka Siber Labs" }], logos: [{ text: "Merdeka Siber", context: "primary" }],
        controls: [{ type: "native_login" }], forms: [], password_fields: [{ form_index: -1 }],
        sensitive_fields: [], inaccessible_frames: 0 } };
      return { ok: true, snapshot: { page_origin: "https://account.example.com", title: "Example account",
        headings: [{ text: "Sign in" }], logos: [], controls: [{ type: "native_login" }],
        forms: [{ relevant: true, action_known: true, action_origin: "https://account.example.com" }],
        password_fields: [{ id: "password-0", form_index: 0 }], sensitive_fields: [], inaccessible_frames: 0 } };
    }
  },
  webNavigation: { onCompleted: on, onBeforeNavigate: { addListener(fn) { beforeNavigate = fn; } } },
  webRequest: { onCompleted: on }
};
globalThis.fetch = async url => {
  const value = String(url);
  if (value.startsWith("file:")) {
    const content = await fs.readFile(new URL(value), "utf8");
    return { ok: true, json: async () => JSON.parse(content), text: async () => content };
  }
  if (value.endsWith("/rdap/dns.json")) return { ok: true, json: async () => ({ services: [[ ["com"], ["https://rdap.example/"] ]] }) };
  if (value === "https://rdap.example/domain/merdekasiber.com") return { ok: true, json: async () => ({
    ldhName: "merdekasiber.com", events: [{ eventAction: "registration", eventDate: "2022-01-01T00:00:00Z" }]
  }) };
  if (value === "https://merdekasiber.com/") return { ok: true, url: value,
    text: async () => '<a href="https://portal.merdekasiber.com/">Lihat Portal</a>' };
  if (value.includes("autocomplete.clearbit.com") && value.includes("query=merdekasiber"))
    return { ok: true, json: async () => [{ name: "Merdeka Siber", domain: "merdekasiber.com" }] };
  if (value === "https://rdap.example/domain/example.com") return { ok: true, json: async () => ({
    ldhName: "example.com", events: [{ eventAction: "registration", eventDate: "2020-01-01T00:00:00Z" }]
  }) };
  if (value.includes("autocomplete.clearbit.com") && value.includes("query=example"))
    return { ok: true, json: async () => [{ name: "Example", domain: "example.com" }] };
  if (value.endsWith("/v2/search/example"))
    return { ok: true, json: async () => [{ name: "Example", domain: "example.com", verified: true }] };
  return { ok: false, status: 404 };
};

await import("../src/background/service-worker.js");
if (!listener) throw new Error("Missing message handler");
const analysis = await new Promise((resolve, reject) => {
  listener({ type: "HEURISHIELD_ANALYZE_PAGE", url: "https://account.example.com/login" },
    { tab: { id: 1, url: "https://account.example.com/login" } },
    response => response?.ok ? resolve(response.analysis) : reject(new Error(response?.error || "No response")));
});
if (analysis.model_result?.model_name !== "XGBoost URL17" || Object.keys(analysis.feature_vector.vector).length !== 17 || analysis.rdap_features.source_domain_age_days < 1) {
  throw new Error(`Wrong model/age: ${JSON.stringify(analysis.model_result)}`);
}
if (analysis.dom_features?.has_password_field !== true || analysis.dom_features?.form_cross_domain !== false || "authorized_domain_match" in (analysis.brand_features || {})) {
  throw new Error(`DOM/Brand integration failed: ${JSON.stringify({ dom: analysis.dom_features, brand: analysis.brand_features })}`);
}
if (analysis.brand_features?.claimed_brand?.name !== "Example" || analysis.brand_features?.candidate_domain_match !== true ||
    analysis.brand_features?.reference_status !== "directory_candidate") {
  throw new Error(`Official brand was not found: ${JSON.stringify(analysis.brand_features)}`);
}
if (analysis.decision_policy?.source !== "url_model" || analysis.decision_policy?.verdict !== analysis.verdict || !Array.isArray(analysis.correlation_rules)) {
  throw new Error(`Decision policy not integrated: ${JSON.stringify(analysis.decision_policy)}`);
}
process.stdout.write(JSON.stringify({ verdict: analysis.verdict, model: analysis.model_result.model_name,
  age: analysis.feature_vector.vector.domain_age_days, featureCount: Object.keys(analysis.feature_vector.vector).length }) + "\n");
const unknown = await new Promise((resolve, reject) => {
  listener({ type: "HEURISHIELD_ANALYZE_PAGE", url: "https://account.example.invalid/login" },
    { tab: { id: 2, url: "https://account.example.invalid/login" } },
    response => response?.ok ? resolve(response.analysis) : reject(new Error(response?.error || "No response")));
});
if (unknown.model_result?.model_name !== "XGBoost URL17" || unknown.rdap_features.source_domain_age_days !== null || 'domain_age_days' in unknown.feature_vector.vector) {
  throw new Error(`Unknown age was not kept unknown: ${JSON.stringify(unknown.model_result)}`);
}
process.stdout.write(JSON.stringify({ verdict: unknown.verdict, model: unknown.model_result.model_name,
  age: unknown.feature_vector.vector.domain_age_days, ageStatus: unknown.model_result.age_status }) + "\n");
beforeNavigate({ frameId: 0, tabId: 3, url: "https://account.example.com/login" });
const redirected = await new Promise((resolve, reject) => {
  listener({ type: "HEURISHIELD_ANALYZE_PAGE", url: "https://www.example.com/welcome" },
    { tab: { id: 3, url: "https://www.example.com/welcome" } },
    response => response?.ok ? resolve(response.analysis) : reject(new Error(response?.error || "No response")));
});
if (redirected.url !== "https://account.example.com/login" || redirected.final_url !== "https://www.example.com/welcome") {
  throw new Error("Original URL was lost on redirect");
}
process.stdout.write(JSON.stringify({ source: redirected.url, final: redirected.final_url }) + "\n");
beforeNavigate({ frameId: 0, tabId: 4, url: "https://www.dicoding.com/login" });
const oauthPage = await new Promise((resolve, reject) => {
  listener({ type: "HEURISHIELD_ANALYZE_PAGE",
    url: "https://accounts.google.com/v3/signin/accountchooser?redirect_uri=https%3A%2F%2Fwww.dicoding.com%2Fsso" },
    { tab: { id: 4 } }, response => response?.ok ? resolve(response.analysis) : reject(new Error(response?.error || "No response")));
});
if (oauthPage.registrable_domain !== "google.com" || oauthPage.hostname !== "accounts.google.com" ||
    !oauthPage.url.startsWith("https://accounts.google.com/") ||
    oauthPage.explanation?.domain !== "accounts.google.com" ||
    oauthPage.rdap_features.source_domain_age_days !== null) {
  throw new Error(`OAuth page reused relying-party identity: ${JSON.stringify({
    url: oauthPage.url, hostname: oauthPage.hostname, domain: oauthPage.registrable_domain,
    age: oauthPage.feature_vector.vector.domain_age_days })}`);
}
process.stdout.write(JSON.stringify({ oauthHost: oauthPage.hostname, oauthDomain: oauthPage.registrable_domain }) + "\n");
const portal = await new Promise((resolve, reject) => {
  listener({ type: "HEURISHIELD_ANALYZE_PAGE", url: "https://portal.merdekasiber.com/" },
    { tab: { id: 5 } }, response => response?.ok ? resolve(response.analysis) : reject(new Error(response?.error || "No response")));
});
if (portal.verdict !== "SAFE" ||
    portal.brand_features?.claimed_brand?.name !== "Merdeka Siber") {
  throw new Error(`Portal false-positive correction failed: ${JSON.stringify({
    raw: portal.model_result.verdict, final: portal.verdict, decision: portal.decision_policy,
    brand: portal.brand_features?.claimed_brand, probability: portal.model_result.probability_phishing })}`);
}
process.stdout.write(JSON.stringify({ portalRaw: portal.model_result.verdict,
  portalFinal: portal.verdict, source: portal.decision_policy.source }) + "\n");

const send = (message, sender = { tab: { id: 6, url: "https://www.example.com/login" } }) =>
  new Promise((resolve, reject) => listener(message, sender,
    response => response?.ok ? resolve(response) : reject(new Error(response?.error || "No response"))));
await send({ type: "HEURISHIELD_TOGGLE_ALLOWLIST", url: "https://www.example.com/login" });
const allowed = (await send({ type: "HEURISHIELD_ANALYZE_PAGE",
  url: "https://www.example.com/login" })).analysis;
if (allowed.verdict !== "SAFE" || allowed.decision_policy?.source !== "manual_allowlist" ||
    allowed.model_result?.ready !== false) throw new Error("Allow list did not override the panel");
await send({ type: "HEURISHIELD_TOGGLE_BLOCKLIST", url: "https://www.example.com/login" });
if (!currentTabUrl.includes("src/warning/warning.html")) throw new Error("Block list did not block the current tab");
const blocked = (await send({ type: "HEURISHIELD_ANALYZE_PAGE",
  url: "https://www.example.com/login" })).analysis;
if (blocked.verdict !== "DANGEROUS" || blocked.decision_policy?.source !== "manual_blocklist") {
  throw new Error("Block list was not reflected in the panel");
}
await send({ type: "HEURISHIELD_TOGGLE_ALLOWLIST", url: "https://www.example.com/login",
  }, { tab: { id: 6, url: currentTabUrl } });
if (currentTabUrl !== "https://www.example.com/login") throw new Error("Allow list did not reopen warning tab");
process.stdout.write("Manual lists applied to panel and current tab OK\n");
