const U = "unknown";
import { TRUSTED_OAUTH_PROVIDER_DOMAINS } from "../../utils/constants.js";
const status = value => value === true ? "matched" : value === false ? "not_matched" : "undetermined";
const and = (...values) => values.includes(false) ? false : values.every(v => v === true) ? true : U;
const or = (...values) => values.includes(true) ? true : values.every(v => v === false) ? false : U;

export function evaluateCorrelation(dom, brand) {
  const claim = brand?.claimed_brand_status === "identified" ? true : brand?.claimed_brand_status === "ambiguous" ? U : false;
  const sensitive = or(dom?.has_password_field ?? U, dom?.has_sensitive_input ?? U);
  const identity = brand?.brand_domain_mismatch ?? U;
  const oauthControl = dom?.controls?.some(c => c.type === "oauth_login") === true;
  const providerMention = oauthControl && (brand?.oauth_providers || []).length > 0;
  const navigation = dom?.navigation;
  const officialProvider = navigation?.observed === true && navigation.destination_type === "official_provider";
  // Without observed destination evidence, an unrecognized IdP is unresolved.
  const badDestination = navigation?.observed === true ? navigation.destination_type === "official_provider" || navigation.destination_type === "same_site" ? false : U : U;
  const crossSensitive = (dom?.forms || []).some(f => f.relevant && f.cross_domain === true && f.destination_verification === false);
  const crossUnknown = (dom?.forms || []).some(f => f.relevant && f.cross_domain === true && f.destination_verification !== true);
  const fakeProvider = claim === true && [...TRUSTED_OAUTH_PROVIDER_DOMAINS]
    .some(domain => domain.split(".")[0] === (brand?.claimed_brand?.name || "").toLowerCase());
  const cases = [
    ["R01", and(claim, brand?.official_domain_match === false ? true : brand?.official_domain_match === U ? U : false), ["B04", "B05"]],
    ["R02", and(claim, identity), ["B04", "B07"]],
    ["R03", and(claim, identity, sensitive), ["B04", "B07", dom?.has_password_field === true ? "D01" : "D02"]],
    ["R04", crossSensitive ? true : crossUnknown ? U : false, ["D03", "D01", "D02"]],
    ["R05", and(dom?.login_redirect_detected ?? U, claim, badDestination), ["D05", "B04"]],
    ["R06", and(oauthControl, providerMention, officialProvider), ["D04", "D05", "B04"]],
    ["R07", and(fakeProvider, identity, sensitive), ["B04", "B07", dom?.has_password_field === true ? "D01" : "D02"]],
    ["R08", brand?.claimed_brand_status === "ambiguous" || brand?.official_domain_match === U || dom?.form_cross_domain === U ? true : false, ["B04", "B05", "D03"]],
    ["R09", brand?.high_confidence_host_impersonation === true, ["B04", "B05"]],
    // A login page can display a platform name (for example WordPress) or a
    // common word that also happens to be a brand. A page claim and password
    // field alone cannot confirm impersonation without a separate host,
    // or form-destination signal.
    ["R10", and(brand?.high_confidence_credential_impersonation ?? U, sensitive,
      or(["exact", "lookalike", "subdomain_exact", "subdomain_lookalike"].includes(brand?.host_brand_claim) ? true : U,
        brand?.brand_domain_mismatch ?? U, crossSensitive ? true : crossUnknown ? U : false)),
      ["B04", "B05", "D01"]]
  ];
  const rules = cases.map(([id, value, evidence_ids]) => ({ id, status: status(value), evidence_ids }));
  // R06 suppresses only an OAuth-related allegation. It never changes URL score.
  return { rules, oauth_context: rules.find(r => r.id === "R06")?.status === "matched",
    strong_credential_impersonation: rules.some(r => ["R03", "R07", "R10"].includes(r.id) && r.status === "matched"),
    strong_brand_impersonation: rules.some(r => r.id === "R09" && r.status === "matched") };
}
