/* Read metadata only. Never inspect field values or submit a form. */
(() => {
  if (globalThis.__hsEvidenceObserver) return;
  globalThis.__hsEvidenceObserver = true;
  const UNKNOWN = "unknown";
  let timer;
  let lastSignature = "";
  let interaction = null;
  const observedRoots = new WeakSet();
  const observers = [];
  const clean = s => String(s || "").replace(/\s+/g, " ").trim().slice(0, 160);
  const origin = value => { try { return new URL(value, location.href).origin; } catch { return null; } };
  const attr = (el, key) => clean(el.getAttribute?.(key));
  const label = el => clean([attr(el, "aria-label"), attr(el, "placeholder"), attr(el, "autocomplete"), attr(el, "name"), attr(el, "id"), attr(el, "type"), el.labels?.[0]?.textContent].filter(Boolean).join(" ")).toLowerCase();
  const visible = el => { try { const s = getComputedStyle(el); return s.display !== "none" && s.visibility !== "hidden" && !!el.getClientRects().length; } catch { return UNKNOWN; } };
  const ownUI = el => el?.closest?.("#heurishield-v5-score-overlay,[data-heurishield]") || el?.getRootNode?.()?.host?.id === "heurishield-v5-score-overlay";
  function all(selector) {
    const out = [];
    const visit = root => {
      try { out.push(...[...root.querySelectorAll(selector)].filter(el => !ownUI(el))); } catch {}
      try { for (const el of root.querySelectorAll("*")) if (el.shadowRoot && !ownUI(el)) visit(el.shadowRoot); } catch {}
    };
    visit(document);
    return out;
  }
  function collect() {
    const fields = all("input,textarea");
    const password = fields.filter(el => el.type === "password" || /(?:^|\s)(?:current-password|new-password)(?:\s|$)/.test(attr(el, "autocomplete")) || (/(?:password|kata sandi|passcode)/i.test(label(el)) && el.type !== "hidden"));
    const sensitive = fields.filter(el => !password.includes(el)).map(el => {
      const meta = label(el);
      const formText = clean(el.form?.getAttribute("aria-label") || el.form?.querySelector("legend")?.textContent).toLowerCase();
      const signature = `${meta} ${formText}`;
      const type = /(?:one-time-code|\botp\b|kode verifikasi|verification code|authenticator|2fa)/i.test(signature) ? "otp" :
        /(?:\bpin\b|personal identification number)/i.test(signature) ? "pin" :
        /(?:cc-number|card number|nomor kartu|credit card)/i.test(signature) ? "card" :
        /(?:cc-csc|\bcvv\b|\bcvc\b)/i.test(signature) ? "cvv" :
        /(?:recovery code|backup code|kode pemulihan)/i.test(signature) ? "recovery" : null;
      return type ? { type, form_index: all("form").indexOf(el.form), visible: visible(el) } : null;
    }).filter(Boolean);
    const forms = all("form").map((form, index) => {
      const raw = attr(form, "action");
      const method = attr(form, "method").toLowerCase();
      const relevant = fields.some(el => el.form === form && (password.includes(el) || sensitive.some(s => s.form_index === index)));
      const jsUnknown = (!raw && (attr(form, "onsubmit") || method === "dialog" || form.querySelector("button[type=button]")));
      return { id: `form-${index}`, relevant, action_origin: jsUnknown ? null : origin(raw || location.href), action_known: !jsUnknown, same_origin: jsUnknown ? UNKNOWN : origin(raw || location.href) === location.origin };
    });
    const controls = all('button,a,input[type="submit"],[role="button"]').map((el, index) => {
      const name = clean([el.innerText, el.textContent, attr(el, "aria-label"), attr(el, "title"), attr(el, "value")].filter(Boolean).join(" "));
      const oauth = /(?:sign in|log in|login|masuk|continue|lanjutkan)\s+(?:with|using|dengan|via)\s+([a-z][\w -]{1,30})/i.exec(name);
      const verification = /(?:verify|verifikasi|otp|2fa)/i.test(name);
      const native = /(?:sign in|log in|login|masuk)/i.test(name);
      if (!oauth && !native && !verification) return null;
      // Keep only the path. OAuth query strings can contain state and account identifiers.
      let targetPath = null;
      try { if (el.href) targetPath = new URL(el.href, location.href).pathname; } catch {}
      return { id: `control-${index}`, type: oauth ? "oauth_login" : verification ? "verification" : "native_login", provider: oauth ? clean(oauth[1]).split(/\s+/)[0] : null, target_origin: el.href ? origin(el.href) : null, target_path: targetPath, text: name.slice(0, 80) };
    }).filter(Boolean);
    const headings = all("h1,h2,h3,h4,h5,h6").filter(el => visible(el) !== false).slice(0, 24).map(el => ({ text: clean(el.textContent), tag: el.tagName.toLowerCase(), in_main: !!el.closest("main,header,form,[role=main]") }));
    const logos = all('img,svg,[role="img"],[class*="logo"],[id*="logo"]').slice(0, 30).map(el => {
      const text = clean([attr(el, "alt"), attr(el, "aria-label"), attr(el, "title"), el.querySelector?.("title")?.textContent].filter(Boolean).join(" "));
      return { text, context: el.closest("button,a") ? "control" : el.closest("footer") ? "footer" : el.closest("header,main,form") ? "primary" : "other" };
    }).filter(x => x.text);
    const inaccessibleFrames = all("iframe").filter(el => { try { return !el.contentDocument; } catch { return true; } }).length;
    const snapshot = { title: clean(document.title), headings, logos, controls, forms, password_fields: password.map((el, i) => ({ id: `password-${i}`, form_index: all("form").indexOf(el.form), visible: visible(el) })), sensitive_fields: sensitive, inaccessible_frames: inaccessibleFrames, observed_at: Date.now(), page_origin: location.origin, interaction: interaction && Date.now() - interaction.at < 15000 ? interaction : null };
    return snapshot;
  }
  function send() {
    const snapshot = collect();
    const signature = JSON.stringify({ ...snapshot, observed_at: 0, interaction: null });
    if (signature === lastSignature) return;
    lastSignature = signature;
    try { chrome.runtime.sendMessage({ type: "HEURISHIELD_EVIDENCE_CHANGED", snapshot }).catch(() => {}); } catch {}
  }
  function schedule() { clearTimeout(timer); timer = setTimeout(send, 650); }
  function observe(root) {
    if (observedRoots.has(root)) return;
    observedRoots.add(root);
    const observer = new MutationObserver(records => {
      if (records.every(record => ownUI(record.target) || [...record.addedNodes].every(ownUI))) return;
      for (const node of records.flatMap(r => [...r.addedNodes])) if (node.shadowRoot && !ownUI(node)) observe(node.shadowRoot);
      schedule();
    });
    observer.observe(root, { childList: true, subtree: true, attributes: true, attributeFilter: ["type", "action", "aria-label", "title", "alt", "placeholder"] });
    observers.push(observer);
  }
  observe(document.documentElement);
  for (const el of all("*")) if (el.shadowRoot) observe(el.shadowRoot);
  document.addEventListener("click", event => {
    if (!event.isTrusted) return;
    const el = event.target?.closest?.('button,a,[role="button"],input[type="submit"]');
    if (!el) return;
    const name = clean([el.textContent, attr(el, "aria-label"), attr(el, "value")].join(" "));
    if (/(?:sign in|log in|login|masuk|continue with|lanjutkan dengan|verify|verifikasi)/i.test(name)) {
      interaction = { at: Date.now(), source_origin: location.origin, type: /(?:with|dengan)/i.test(name) ? "oauth_login" : "native_login", provider: /(?:with|dengan)\s+([a-z]+)/i.exec(name)?.[1] || null };
      try { chrome.runtime.sendMessage({ type: "HEURISHIELD_LOGIN_INTERACTION", interaction }).catch(() => {}); } catch {}
    }
  }, true);
  chrome.runtime.onMessage.addListener((message, _sender, respond) => {
    if (message?.type === "HEURISHIELD_COLLECT_EVIDENCE") { respond({ ok: true, snapshot: collect() }); return false; }
    return false;
  });
  window.addEventListener("pagehide", () => { clearTimeout(timer); observers.forEach(o => o.disconnect()); }, { once: true });
  schedule();
})();
