import assert from "node:assert/strict";
import { parentSiteLinksToPage } from "../src/analyzer/brand/parent-site-link.js";

const fetcher = async url => {
  assert.equal(url, "https://merdekasiber.com/");
  return { ok: true, text: async () => '<a href="https://portal.merdekasiber.com">Lihat Portal Peserta</a>' };
};
assert.equal(await parentSiteLinksToPage("https://portal.merdekasiber.com/", fetcher), true);
assert.equal(await parentSiteLinksToPage("https://merdekasiber.com/", fetcher), false);
assert.equal(await parentSiteLinksToPage("http://portal.merdekasiber.com/", fetcher), false);
assert.equal(await parentSiteLinksToPage("https://portal.merdekasiber.com.evil.test/", fetcher), false);
assert.equal(await parentSiteLinksToPage("https://login.cobalink.test/", async () => ({ ok: true,
  url: "https://attacker.example/", text: async () => '<a href="https://login.cobalink.test/">Login</a>' })), false);
assert.equal(await parentSiteLinksToPage("https://signin.example.test/", async () => {
  throw new Error("Must not fetch an apex host");
}), false);
console.log("Parent site link OK: observed subdomain link, apex, HTTP, deceptive host");
