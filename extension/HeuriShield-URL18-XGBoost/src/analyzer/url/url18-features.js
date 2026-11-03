/* The 17 URL text features use the same definitions as ekstrak_fitur_url.py. */
import { parse as parseDomain } from "../../shared/tldts.js";

const SENSITIVE = new Set([
  "account", "admin", "auth", "confirm", "login", "logon", "otp",
  "password", "reset", "secure", "signin", "update", "verification", "verify"
]);

const length = value => Array.from(value).length;
const count = (value, character) => Array.from(value).filter(item => item === character).length;
const round6 = value => Math.round((value + Number.EPSILON) * 1e6) / 1e6;

function entropy(value) {
  const chars = Array.from(value);
  if (!chars.length) return 0;
  const counts = new Map();
  for (const char of chars) counts.set(char, (counts.get(char) || 0) + 1);
  let result = 0;
  for (const n of counts.values()) {
    const p = n / chars.length;
    result -= p * Math.log2(p);
  }
  return round6(result);
}

function unquote(value) {
  // decodeURIComponent rejects broken escapes; Python unquote preserves them.
  try { return decodeURIComponent(value); } catch { return value.replace(/%([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16))); }
}

export function extractUrl18Features(input) {
  const raw = String(input || "").trim();
  const match = /^(https?):\/\/([^/?#]*)([^?#]*)(?:\?([^#]*))?/i.exec(raw);
  if (!match) throw new Error("URL must have http(s) scheme and hostname");
  const parsed = new URL(raw);
  let host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  // tldts rejects a label beginning/ending with '-', while tldextract still
  // counts it. Sanitize only for suffix parsing; numeric features use raw host.
  const parserHost = host.split(".").map(label => label.replace(/^-+|-+$/g, "") || "x").join(".");
  const isIp = host.includes(":") || parseDomain(host).isIp === true;
  const subdomain = isIp ? "" : parseDomain(parserHost, { allowPrivateDomains: true }).subdomain || "";
  const path = match[3] || "/";
  const query = match[4] || "";
  const pathQuery = path + query;
  const tokens = (unquote(path) + "?" + unquote(query)).toLowerCase().match(/[A-Za-z0-9]+/g) || [];
  const digits = (host.match(/[0-9]/g) || []).length;
  return {
    url_length: length(raw),
    hostname_length: length(host),
    path_length: length(path),
    query_length: length(query),
    subdomain_count: subdomain ? subdomain.split(".").filter(Boolean).length : 0,
    path_depth: path.split("/").filter(Boolean).length,
    dot_count: count(host, "."),
    hyphen_count: count(host, "-"),
    digit_ratio: round6(digits / length(host)),
    special_char_count: (pathQuery.match(/[^A-Za-z0-9]/g) || []).length,
    has_at_symbol: raw.includes("@") ? 1 : 0,
    has_ip_host: isIp ? 1 : 0,
    has_https_scheme: match[1].toLowerCase() === "https" ? 1 : 0,
    hostname_entropy: entropy(host),
    sensitive_token_count: tokens.filter(token => SENSITIVE.has(token)).length,
    url_entropy: entropy(raw),
    path_hyphen_count: count(path, "-")
  };
}

export function ageLookupDomain(url) {
  const host = new URL(url).hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host.includes(":") || parseDomain(host).isIp) return null;
  const parserHost = host.split(".").map(label => label.replace(/^-+|-+$/g, "") || "x").join(".");
  // Keep original spelling if invalid syntax appears in the registered label.
  const parsed = parseDomain(parserHost, { allowPrivateDomains: false });
  if (!parsed.domain) return host;
  const count = parsed.domain.split(".").length;
  return host.split(".").slice(-count).join(".");
}
