// Preserve the URL shape while dropping authentication material from persisted data.
export function sanitizeAuditUrl(raw) {
  try {
    const url = new URL(raw);
    url.username = "";
    url.password = "";
    url.hash = "";
    for (const key of [...url.searchParams.keys()]) {
      if (/(?:code|state|token|secret|nonce|key|password|pass|otp|auth|session|ticket|credential|client_id|redirect_uri)/i.test(key)) url.searchParams.delete(key);
    }
    return url.toString();
  } catch { return ""; }
}
