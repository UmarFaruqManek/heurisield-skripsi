/** Pure policy evaluation. Caller supplies the saved, observed age and config. */
export function classifyDomainAge(value, policy) {
  const numeric = typeof value === "number" && Number.isFinite(value) && value >= 0;
  if (!numeric) {
    return { policy_version: policy.version, domain_age_days: null,
      category: policy.unknown.id, label: policy.unknown.label,
      supporting_risk_signal: "unknown", standalone_verdict_change: false };
  }
  const days = Math.floor(value);
  const category = policy.categories.find(item => days >= item.min_days &&
    (item.max_days === null || days <= item.max_days));
  if (!category) throw new Error("Domain age category missing from policy");
  return { policy_version: policy.version, domain_age_days: value,
    category: category.id, label: category.label,
    supporting_risk_signal: days <= policy.supporting_signal_max_days,
    standalone_verdict_change: false };
}
