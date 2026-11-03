/* Age is observed from the registration date; missing remains unknown. */
import { ageLookupDomain } from "../url/url18-features.js";

let ianaPromise;
const cache = new Map();
const PROVIDERS = [
  domain => `https://api-check-beryl-beta.vercel.app/api/whois?domain=${encodeURIComponent(domain)}`,
  domain => `https://whois-api-dun.vercel.app/api/whois?domain=${encodeURIComponent(domain)}`,
  domain => `https://who-dat.as93.net/${encodeURIComponent(domain)}`
];

async function getJson(url, timeout = 6500) {
  const response = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(timeout) });
  if (!response.ok) throw new Error(`http_${response.status}`);
  return response.json();
}

async function ianaServers() {
  if (!ianaPromise) {
    ianaPromise = getJson("https://data.iana.org/rdap/dns.json", 9000).then(data => {
      const map = new Map();
      for (const [suffixes, urls] of data.services || []) {
        for (const suffix of suffixes) if (urls?.[0]) map.set(suffix.toLowerCase(), urls[0]);
      }
      return map;
    }).catch(() => new Map());
  }
  return ianaPromise;
}

function dates(payload) {
  const data = payload?.data && typeof payload.data === "object" ? payload.data : payload;
  const event = data?.events?.find(item => String(item.eventAction).toLowerCase() === "registration")?.eventDate;
  return { domain: String(data?.domain || data?.ldhName || "").toLowerCase().replace(/\.$/, ""),
    date: data?.domain_creation_date || data?.creation_date || data?.creationDate ||
      data?.registered_on || data?.registeredOn || data?.created || data?.dates?.created || event };
}

function observed(payload, queriedDomain, provider) {
  const item = dates(payload);
  if (item.domain && item.domain !== queriedDomain) return null;
  const created = Date.parse(item.date);
  if (!Number.isFinite(created) || created > Date.now()) return null;
  // Python's RDAP evaluator subtracts UTC calendar dates, not elapsed hours.
  const now = new Date();
  const registration = new Date(created);
  const days = Math.round((Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()) -
    Date.UTC(registration.getUTCFullYear(), registration.getUTCMonth(), registration.getUTCDate())) / 86400000);
  return { status: "observed", days, domain: queriedDomain, created_at: new Date(created).toISOString(), provider };
}

export async function lookupUrl18Age(url) {
  const domain = ageLookupDomain(url);
  if (!domain) return { status: "unknown", days: null, reason: "ip_host" };
  const cached = cache.get(domain);
  if (cached && Date.now() - cached.checked_at < (cached.days === null ? 5 * 60000 : 24 * 3600000)) return cached;
  const attempts = [];
  const suffix = domain.split(".").at(-1);
  const server = (await ianaServers()).get(suffix);
  const urls = [
    ...(server ? [{ provider: "registry_rdap", url: new URL(`domain/${encodeURIComponent(domain)}`, server.endsWith("/") ? server : server + "/").href }] : []),
    ...PROVIDERS.map((makeUrl, index) => ({ provider: ["beryl", "dun", "who-dat"][index], url: makeUrl(domain) }))
  ];
  for (const item of urls) {
    try {
      const payload = await getJson(item.url);
      const result = observed(payload, domain, item.provider);
      if (result) {
        const saved = { ...result, checked_at: Date.now(), attempts };
        cache.set(domain, saved);
        return saved;
      }
      attempts.push({ provider: item.provider, status: "no_registration_date" });
    } catch (error) {
      attempts.push({ provider: item.provider, status: error?.message || "lookup_failed" });
    }
  }
  const result = { domain, status: "unknown", days: null, checked_at: Date.now(), attempts };
  cache.set(domain, result);
  return result;
}
