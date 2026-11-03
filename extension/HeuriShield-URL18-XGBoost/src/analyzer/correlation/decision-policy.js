/* URL score remains the baseline; corroborated DOM and brand evidence can
 * correct a narrow class of false positives or confirmed impersonation. */
import { TRUSTED_OAUTH_PROVIDER_DOMAINS } from "../../utils/constants.js";

function verifiedProviderAuthorizationPage(brand, dom, context) {
  let page;
  try { page = new URL(context.pageUrl || ""); } catch { return false; }
  if (page.protocol !== "https:" || !context.mainSnapshot ||
      context.mainSnapshot.page_origin !== page.origin ||
      !(dom?.observed_frame_count > 0)) return false;
  const root = brand?.verified_reference_domain;
  if (!root || !TRUSTED_OAUTH_PROVIDER_DOMAINS.has(root) ||
      (page.hostname !== root && !page.hostname.endsWith(`.${root}`))) return false;
  if (brand.claimed_brand_status !== "identified" ||
      brand.official_domain_match !== true ||
      brand.brand_claim_relation !== "own_domain") return false;
  // A provider's own authorization page is identified by its HTTPS host,
  // verified provider reference, and OAuth request shape. The relying party
  // in redirect_uri is never treated as proof that the app is trustworthy.
  const oauthPath = /(?:^|\/)(?:signin|oauth|authorize|accountchooser|auth)(?:\/|$)/i.test(page.pathname);
  const oauthRequest = page.searchParams.has("client_id") &&
    page.searchParams.has("redirect_uri") &&
    (page.searchParams.has("response_type") || page.searchParams.has("scope"));
  const forms = dom.forms || [];
  return oauthPath && oauthRequest && context.sameSite === true &&
    !(forms.some(form => form.relevant && form.cross_domain === true)) &&
    dom.form_cross_domain !== true;
}

export function decideWithEvidence(urlVerdict, dom, brand, correlation, context = {}) {
  if (urlVerdict !== "SAFE" && urlVerdict !== "DANGEROUS") {
    return { verdict: "LIMITED", source: "url_unavailable", review_candidate: false, review_reason: null };
  }
  if (correlation?.strong_credential_impersonation === true) {
    return { verdict: "DANGEROUS", source: "confirmed_credential_impersonation", review_candidate: false, review_reason: null };
  }
  if (correlation?.strong_brand_impersonation === true) {
    return { verdict: "DANGEROUS", source: "corroborated_brand_impersonation", review_candidate: false, review_reason: null };
  }

  // This is audit metadata, not an allowlist or an automatic SAFE override.
  const verifiedBrand = brand?.claimed_brand_status === "identified" &&
    brand.official_domain_match === true;
  const sensitiveForm = (dom?.has_password_field === true || dom?.has_sensitive_input === true) &&
    (dom.forms || []).some(form => form.relevant && form.cross_domain === false);
  const noConfirmedConflict = brand?.brand_domain_mismatch !== true &&
    !(correlation?.rules || []).some(rule => ["R03", "R04", "R05", "R07", "R09", "R10"].includes(rule.id) && rule.status === "matched");
  // Page title, logo and form action are controlled by the visited site.
  // An automatic SAFE correction also needs independent evidence: a link
  // from the parent domain to this exact subdomain.
  const sameDomainForm = dom?.form_cross_domain === false &&
    (dom.forms || []).some(form => form.relevant && form.cross_domain === false);
  const chosenName = String(brand?.claimed_brand?.name || "").toLowerCase().trim();
  const conflictingVerifiedClaim = (brand?.candidates || []).some(candidate =>
    candidate.verified === true && candidate.claim === true &&
    // A parent name contained in the exact first-party brand name (Google /
    // Google Antigravity) is not a competing page identity by itself.
    !(candidate.name && chosenName.split(/\W+/).includes(String(candidate.name).toLowerCase().trim())) &&
    candidate.domain !== brand?.claimed_brand?.official_domain &&
    candidate.domain !== context.pageRegistrableDomain &&
    (candidate.in_title === true || candidate.in_logo === true));
  if (urlVerdict === "DANGEROUS" && verifiedProviderAuthorizationPage(brand, dom, context) &&
      !conflictingVerifiedClaim && noConfirmedConflict) {
    return { verdict: "SAFE", source: "verified_oauth_provider_page",
      review_candidate: false, review_reason: null };
  }
  const ownDomainCorroborated = urlVerdict === "DANGEROUS" &&
    brand?.claimed_brand_status === "identified" &&
    brand.brand_claim_relation === "own_domain" &&
    brand.brand_in_title === true &&
    (brand.brand_in_heading === true || brand.brand_in_logo === true) &&
    !conflictingVerifiedClaim &&
    brand.official_domain_match !== false &&
    dom?.has_password_field === true &&
    dom?.form_cross_domain !== true &&
    context.parentSiteLink === true &&
    context.sameSite === true &&
    Number.isFinite(context.domainAgeDays) && context.domainAgeDays >= 1095 &&
    Number.isFinite(context.probability) && context.probability < 0.60 &&
    noConfirmedConflict;
  if (ownDomainCorroborated) {
    return { verdict: "SAFE", source: "corroborated_own_domain_review",
      review_candidate: false, review_reason: null,
      corroboration: "parent_site_link" };
  }
  // A verified API/IdP reference that matches the visited registrable domain
  // is independent of the page's self-description. It can correct a moderate
  // URL false positive on a first-party login when the observed form stays on
  // that origin. A mere candidate match or a copied brand name cannot qualify.
  const verifiedOfficialLogin = urlVerdict === "DANGEROUS" &&
    verifiedBrand && brand.brand_claim_relation === "own_domain" &&
    (brand.candidates || []).some(candidate =>
      candidate.claim === true && candidate.name === brand.claimed_brand?.name &&
      candidate.domain === brand.verified_reference_domain &&
      candidate.in_title === true &&
      (candidate.in_heading === true || candidate.in_logo === true)) &&
    !conflictingVerifiedClaim && dom?.has_password_field === true &&
    dom.form_cross_domain === false &&
    (dom.forms || []).some(form => form.relevant && form.cross_domain === false &&
      form.same_origin === true) &&
    context.mainSnapshot?.page_origin?.startsWith("https://") &&
    context.sameSite === true &&
    Number.isFinite(context.domainAgeDays) && context.domainAgeDays >= 1095 &&
    Number.isFinite(context.probability) && context.probability < 0.60 &&
    noConfirmedConflict;
  if (verifiedOfficialLogin) {
    return { verdict: "SAFE", source: "verified_own_domain_login",
      review_candidate: false, review_reason: null };
  }
  // Documentation on an independently verified first-party domain may be
  // younger than three years and receive a high lexical URL score. Require
  // an exact verified reference, the observed HTTPS page, and no sensitive
  // fields or cross-domain credential form; a copied brand cannot qualify.
  let documentationPage = false;
  try {
    const page = new URL(context.pageUrl || "");
    documentationPage = /^\/docs(?:\/|$)/i.test(page.pathname) && page.protocol === "https:" &&
      context.mainSnapshot?.page_origin === page.origin;
  } catch {}
  const verifiedDocumentationPage = urlVerdict === "DANGEROUS" && verifiedBrand &&
    brand.brand_claim_relation === "own_domain" &&
    brand.verified_reference_domain === context.pageRegistrableDomain &&
    brand.brand_in_title === true && !conflictingVerifiedClaim &&
    documentationPage && context.sameSite === true &&
    dom?.observed_frame_count > 0 && dom.has_password_field === false &&
    dom.has_sensitive_input === false && dom.form_cross_domain === false &&
    noConfirmedConflict && Number.isFinite(context.probability) &&
    context.probability < 0.90;
  if (verifiedDocumentationPage) {
    return { verdict: "SAFE", source: "verified_own_domain_documentation_page",
      review_candidate: false, review_reason: null };
  }
  // Search result headings and titles can mention other brands. They describe
  // the query, not the identity of this independently verified first-party
  // search host. Unknown forms/iframes are not evidence of exfiltration;
  // observed credential fields and cross-domain forms remain disqualifying.
  let searchPage = false;
  try {
    const page = new URL(context.pageUrl || "");
    searchPage = page.protocol === "https:" && page.pathname === "/search" &&
      page.searchParams.has("q") && context.mainSnapshot?.page_origin === page.origin;
  } catch {}
  const verifiedSearchPage = urlVerdict === "DANGEROUS" && verifiedBrand &&
    brand.brand_claim_relation === "own_domain" &&
    brand.verified_reference_domain === context.pageRegistrableDomain &&
    brand.brand_in_title === true &&
    noConfirmedConflict && searchPage &&
    context.sameSite === true && dom?.observed_frame_count > 0 &&
    dom.has_password_field !== true && dom.has_sensitive_input !== true &&
    dom.form_cross_domain !== true &&
    (dom.password_fields || []).length === 0 &&
    (dom.sensitive_fields || []).length === 0 &&
    (context.mainSnapshot.password_fields || []).length === 0 &&
    (context.mainSnapshot.sensitive_fields || []).length === 0 &&
    !(dom.forms || []).some(form => form.relevant && form.cross_domain === true) &&
    Number.isFinite(context.domainAgeDays) && context.domainAgeDays >= 1095 &&
    Number.isFinite(context.probability) && context.probability < 0.60;
  if (verifiedSearchPage) {
    return { verdict: "SAFE", source: "verified_own_domain_search_page",
      review_candidate: false, review_reason: null };
  }
  // A long query string can raise the URL score on an ordinary page of an
  // independently verified first-party domain. This narrow correction needs
  // an observed, non-sensitive HTTPS page; a copied brand on another host
  // cannot qualify. Keep high URL scores and any conflicting evidence blocked.
  const officialNonSensitivePage = urlVerdict === "DANGEROUS" &&
    verifiedBrand && brand.brand_claim_relation === "own_domain" &&
    dom?.observed_frame_count > 0 &&
    dom.has_password_field === false && dom.has_sensitive_input === false &&
    dom.form_cross_domain === false && noConfirmedConflict &&
    context.mainSnapshot?.page_origin?.startsWith("https://") &&
    context.sameSite === true &&
    Number.isFinite(context.domainAgeDays) && context.domainAgeDays >= 1095 &&
    Number.isFinite(context.probability) && context.probability < 0.60;
  if (officialNonSensitivePage) {
    return { verdict: "SAFE", source: "verified_own_domain_non_sensitive_page",
      review_candidate: false, review_reason: null };
  }
  // Even all of these page-local signals can be copied by an attacker.
  // Preserve them for review, never as an automatic SAFE override.
  const identity = String(context.pageRegistrableDomain || "").split(".")[0]
    .replace(/[^a-z0-9]/gi, "").toLowerCase();
  const snapshot = context.mainSnapshot || {};
  const mentionsIdentity = value => String(value || "").replace(/[^a-z0-9]/gi, "")
    .toLowerCase().includes(identity);
  const titleMatches = identity.length >= 6 && mentionsIdentity(snapshot.title);
  const logoMatches = identity.length >= 6 && (snapshot.logos || []).some(logo =>
    mentionsIdentity(logo.text));
  const googleRoute = (dom?.controls || []).some(control =>
    control.type === "oauth_login" && /^google$/i.test(control.provider || "") &&
    control.target_origin === snapshot.page_origin &&
    /^\/(?:auth|login|oauth)\/google\/(?:redirect|login|start)\/?$/i.test(control.target_path || ""));
  const localLoginReview = urlVerdict === "DANGEROUS" &&
    brand?.claimed_brand_status === "unknown" && noConfirmedConflict &&
    dom?.has_password_field === true && sameDomainForm &&
    (dom.forms || []).some(form => form.relevant && form.same_origin === true) &&
    dom?.form_cross_domain === false && googleRoute && titleMatches && logoMatches &&
    snapshot.page_origin?.startsWith("https://") && context.sameSite === true &&
    Number.isFinite(context.domainAgeDays) && context.domainAgeDays >= 1095 &&
    Number.isFinite(context.probability) && context.probability < 0.45;
  const officialLogin = verifiedBrand && sensitiveForm && noConfirmedConflict;
  const observedOAuth = correlation?.oauth_context === true && noConfirmedConflict;
  const reviewCandidate = urlVerdict === "DANGEROUS" &&
    (localLoginReview || officialLogin || observedOAuth);
  return {
    verdict: urlVerdict,
    source: "url_model",
    review_candidate: reviewCandidate,
    review_reason: reviewCandidate ? localLoginReview ? "local_login_unverified" :
      officialLogin ? "verified_brand_login" : "observed_official_oauth_navigation" : null
  };
}
