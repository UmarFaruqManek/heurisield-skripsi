import { ageLookupDomain } from "../url/url18-features.js";

const cache = new Map();

// A link from the registrable domain to its subdomain is independent of the
// subdomain's own title/logo. Fetch only for a narrow false-positive review.
export async function parentSiteLinksToPage(pageUrl, fetcher = fetch) {
  let page;
  try { page = new URL(pageUrl); } catch { return false; }
  if (page.protocol !== "https:") return false;
  const root = ageLookupDomain(pageUrl);
  if (!root || page.hostname === root || !page.hostname.endsWith(`.${root}`)) return false;
  const key = `${root}:${page.hostname}`;
  const previous = cache.get(key);
  if (previous && Date.now() < previous.expires) return previous.found;
  let found = false;
  try {
    const response = await fetcher(`https://${root}/`, { signal: AbortSignal.timeout(4500) });
    if (response.ok) {
      // A redirect to a different owner cannot corroborate the subdomain.
      if (response.url) {
        const responseHost = new URL(response.url).hostname;
        if (responseHost !== root && responseHost !== `www.${root}`) {
          cache.set(key, { found: false, expires: Date.now() + 5 * 60000 });
          return false;
        }
      }
      const html = (await response.text()).slice(0, 1_000_000);
      const links = html.matchAll(/<a\b[^>]{0,1000}\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')/gi);
      for (const match of links) {
        try {
          const target = new URL(match[1] || match[2], `https://${root}/`);
          if (target.protocol === "https:" && target.hostname === page.hostname) { found = true; break; }
        } catch {}
      }
    }
  } catch {}
  cache.set(key, { found, expires: Date.now() + (found ? 6 * 3600000 : 5 * 60000) });
  return found;
}
