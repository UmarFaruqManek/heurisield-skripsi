import { parse as parseDomain } from "../../shared/tldts.js";

const UNKNOWN = "unknown";
export function registrable(host) {
  try { return parseDomain(new URL(host).hostname.toLowerCase().replace(/\.$/, ""), { allowPrivateDomains: true }).domain || null; }
  catch { return null; }
}

export function analyzeDomEvidence(snapshots, navigation = null) {
  const frames = (snapshots || []).filter(s => s && typeof s === "object");
  if (!frames.length) return { has_password_field: UNKNOWN, has_sensitive_input: UNKNOWN, form_cross_domain: UNKNOWN, login_button_detected: UNKNOWN, login_redirect_detected: UNKNOWN, forms: [], controls: [], sensitive_field_types: [], unresolved_checks: ["dom_unavailable"] };
  const password = frames.flatMap(s => s.password_fields || []);
  const sensitive = frames.flatMap(s => s.sensitive_fields || []);
  const controls = frames.flatMap(s => s.controls || []);
  const inaccessibleCount = frames.reduce((n, s) => n + Number(s.inaccessible_frames || 0), 0);
  // A cross-origin iframe may be unreadable from its parent yet readable by a
  // permitted all_frames content script. Count only frames still unobserved.
  const incomplete = inaccessibleCount > Math.max(0, frames.length - 1);
  const forms = frames.flatMap((s, frameIndex) => (s.forms || []).map(f => {
    const source = registrable(s.page_origin);
    const target = registrable(f.action_origin);
    const status = !f.action_known || !source || !target ? UNKNOWN : source !== target;
    return { ...f, frame_index: frameIndex, cross_domain: status, source_registrable_domain: source, destination_registrable_domain: target };
  }));
  const relevant = forms.filter(f => f.relevant);
  const cross = relevant.some(f => f.cross_domain === true) ? true : relevant.some(f => f.cross_domain === UNKNOWN) || incomplete ? UNKNOWN : false;
  return {
    observed_at: Math.max(...frames.map(s => Number(s.observed_at || 0))),
    observed_frame_count: frames.length,
    has_password_field: password.length ? true : incomplete ? UNKNOWN : false,
    has_sensitive_input: sensitive.length ? true : incomplete ? UNKNOWN : false,
    form_cross_domain: relevant.length ? cross : incomplete ? UNKNOWN : false,
    login_button_detected: controls.length ? true : incomplete ? UNKNOWN : false,
    login_redirect_detected: navigation?.observed === true ? true : navigation?.observation_complete ? false : UNKNOWN,
    password_fields: password, sensitive_fields: sensitive,
    sensitive_field_types: [...new Set(sensitive.map(f => f.type))],
    forms, controls,
    navigation: navigation || null,
    unresolved_checks: incomplete ? ["inaccessible_iframe"] : []
  };
}
