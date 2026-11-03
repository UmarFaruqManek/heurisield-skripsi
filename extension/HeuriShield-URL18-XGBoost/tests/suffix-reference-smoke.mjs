import fs from "node:fs/promises";
import { auditDomainSuffix } from "../src/model/suffix-reference.js";

globalThis.chrome = { runtime: { getURL: path => new URL("../" + path, import.meta.url).href } };
globalThis.fetch = async url => ({ text: () => fs.readFile(new URL(url), "utf8") });

for (const [url, registration, site] of [
  ["https://kkn.uho.ac.id/login", "uho.ac.id", "uho.ac.id"],
  ["https://facebook-247-support.blogspot.com/login", "blogspot.com", "facebook-247-support.blogspot.com"],
  ["https://tenant.pages.dev/account", "pages.dev", "tenant.pages.dev"],
  ["https://avio-occasionali.enac.gov.it/login", "enac.gov.it", "enac.gov.it"]
]) {
  const audit = await auditDomainSuffix(url);
  if (!audit.tld_known || audit.snapshot_registration_domain !== registration || audit.snapshot_site_domain !== site) {
    throw new Error(`${url}: ${JSON.stringify(audit)}`);
  }
  process.stdout.write(`${new URL(url).hostname}: ${registration} / ${site}\n`);
}
