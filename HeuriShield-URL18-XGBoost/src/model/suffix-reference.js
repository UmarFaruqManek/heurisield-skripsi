/* Audit the user's IANA TLD/PSL snapshots without changing frozen model features. */
import { parse as parseDomain } from "../shared/tldts.js";

let referencePromise;

function publicSuffix(labels, rules) {
  let selected = 1;
  for (let start = 0; start < labels.length; start++) {
    const candidate = labels.slice(start).join(".");
    if (rules.has("!" + candidate)) return labels.slice(start + 1).join(".");
    if (rules.has(candidate)) selected = Math.max(selected, labels.length - start);
    if (start + 1 < labels.length && rules.has("*." + labels.slice(start + 1).join("."))) {
      selected = Math.max(selected, labels.length - start);
    }
  }
  return labels.slice(-selected).join(".");
}

function siteFromRules(host, rules) {
  const labels = host.split(".");
  const suffix = publicSuffix(labels, rules);
  const suffixLength = suffix.split(".").length;
  return labels.length > suffixLength ? labels.slice(-(suffixLength + 1)).join(".") : null;
}

async function loadReference() {
  if (!referencePromise) referencePromise = Promise.all([
    fetch(chrome.runtime.getURL("src/model/iana_tld_2026-10-29.txt")).then(r => r.text()),
    fetch(chrome.runtime.getURL("src/model/public_suffix_list_2026-10-29.dat")).then(r => r.text())
  ]).then(([ianaText, pslText]) => {
    const tlds = new Set(ianaText.split(/\r?\n/).map(x => x.trim().toLowerCase()).filter(x => x && !x.startsWith("#")));
    const icann = new Set();
    const full = new Set();
    let privateRules = false;
    for (const raw of pslText.split(/\r?\n/)) {
      const line = raw.trim().toLowerCase();
      if (line.includes("begin private domains")) privateRules = true;
      if (!line || line.startsWith("//")) continue;
      full.add(line);
      if (!privateRules) icann.add(line);
    }
    return { tlds, icann, full };
  });
  return referencePromise;
}

export async function auditDomainSuffix(url) {
  const host = new URL(url).hostname.toLowerCase().replace(/\.$/, "");
  const labels = host.split(".");
  const reference = await loadReference();
  const currentPublic = parseDomain(host, { allowPrivateDomains: false }).domain || null;
  const currentSite = parseDomain(host, { allowPrivateDomains: true }).domain || null;
  const snapshotPublic = siteFromRules(host, reference.icann);
  const snapshotSite = siteFromRules(host, reference.full);
  return {
    tld_known: reference.tlds.has(labels.at(-1)),
    snapshot_registration_domain: snapshotPublic,
    snapshot_site_domain: snapshotSite,
    model_parser_registration_domain: currentPublic,
    model_parser_site_domain: currentSite,
    snapshot_differs: snapshotPublic !== currentPublic || snapshotSite !== currentSite
  };
}
