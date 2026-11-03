/* Jelaskan bukti yang teramati; pisahkan hasil model URL dari koreksi DOM/brand. */
export function buildAnalysisExplanation(analysis = {}) {
  if (analysis.model_result?.model_family === "XGBoost") {
    const verdict = analysis.verdict;
    const urlVerdict = analysis.model_result.verdict ||
      (analysis.model_result.predicted_label === "phishing" ? "DANGEROUS" :
        analysis.model_result.predicted_label === "legitimate" ? "SAFE" : null);
    const decisionSource = analysis.decision_policy?.source;
    const changed = urlVerdict && urlVerdict !== verdict;
    const summary = verdict === "LIMITED" ? "Pemeriksaan belum lengkap." : changed
      ? verdict === "DANGEROUS"
        ? "Bukti identitas situs mengubah penilaian alamat menjadi phishing."
        : decisionSource === "verified_own_domain_non_sensitive_page"
          ? "Domain resmi dan halaman tanpa permintaan data sensitif mengoreksi penilaian alamat."
          : decisionSource === "verified_oauth_provider_page"
            ? "Halaman login berada pada domain resmi penyedia identitas; pola URL yang panjang dikoreksi oleh pemeriksaan identitas."
          : decisionSource === "verified_own_domain_login"
            ? "Domain brand yang terverifikasi dan tujuan formulir pada situs yang sama mengoreksi penilaian alamat."
            : "Bukti identitas dan halaman mengubah penilaian alamat menjadi legitimate."
      : ["confirmed_credential_impersonation", "corroborated_brand_impersonation"].includes(decisionSource)
        ? "Pemeriksaan identitas situs mendukung peringatan dari analisis alamat."
      : "Keputusan akhir mengikuti penilaian alamat situs.";
    // Tiga baris yang sama dipakai panel dan halaman blokir; tidak tampilkan
    // angka fitur, aturan internal, atau klaim kepemilikan yang belum terbukti.
    const brandReason = analysis.brand_features?.claimed_brand_status === "unknown"
      ? null : brandExplanation(analysis.brand_features, analysis.final_url || analysis.url);
    const reasons = [
      decisionSource === "verified_oauth_provider_page"
        ? "Alamat: halaman otorisasi berada pada domain resmi penyedia login. Alamat tujuan aplikasi tetap perlu diperiksa secara terpisah."
        : decisionSource === "verified_own_domain_login"
        ? "Alamat: model menandai risiko, tetapi domain brand terverifikasi cocok dan formulir login tetap pada situs ini."
        : decisionSource === "verified_own_domain_non_sensitive_page"
        ? "Alamat: pola URL melewati ambang model, tetapi pemeriksaan domain resmi dan halaman mengoreksi keputusan."
        : urlVerdict === "DANGEROUS" ? "Alamat: dinilai phishing oleh model."
        : urlVerdict === "SAFE" ? "Alamat: dinilai legitimate oleh model."
          : "Alamat: penilaian belum tersedia.",
      ...(brandReason ? [brandReason] : []),
      domExplanation(analysis.dom_features)
    ];
    const limitation = analysis.dom_features?.unresolved_checks?.includes("inaccessible_iframe")
      ? "Sebagian isi halaman tidak dapat diperiksa."
      : analysis.decision_policy?.review_reason === "local_login_unverified"
        ? "Formulir dan tombol Google tampak sesuai, tetapi identitas situs belum terverifikasi. Keputusan tetap mengikuti penilaian alamat."
      : decisionSource === "url_model" && analysis.decision_policy?.review_candidate
        ? "Ada bukti yang perlu ditinjau; keputusan tetap mengikuti penilaian alamat."
        : "";
    return {
      title: verdict === "DANGEROUS" ? "Terindikasi phishing" : verdict === "SAFE" ? "Tidak ditemukan indikasi phishing kuat" : "Pemeriksaan belum lengkap",
      summary,
      domain: hostname(analysis.final_url || analysis.url),
      reasons,
      action: verdict === "DANGEROUS"
        ? "Jangan masukkan kata sandi atau kode verifikasi sebelum memastikan alamat situs."
        : "Periksa alamat situs sebelum memasukkan kata sandi atau data pribadi.",
      limitation
    };
  }
  const brand = analysis.brand_features || {}, url = analysis.url_features || {};
  const model = analysis.model_result || {}, rdap = analysis.rdap_features || {};
  const dangerous = analysis.verdict === "DANGEROUS", safe = analysis.verdict === "SAFE";
  const manual = (analysis.matched_rules || []).some(rule => rule.id === "MANUAL_BLOCKLIST");
  const domain = analysis.hostname || analysis.domain || hostname(analysis.final_url || analysis.originalUrl || analysis.url);
  const reasons = [];
  const add = reason => { if (reason && !reasons.includes(reason)) reasons.push(reason); };
  if (manual) {
    add("Domain ini ada di daftar blokir yang Anda buat.");
  } else if (dangerous) {
    if (model.post_model_guard) add(guardReason(model.post_model_guard));
    if (model.ready && model.raw_verdict !== "SAFE") {
      add(brandRuleReason(model, brand, url, domain));
      add(ageRuleReason(model, rdap, url, domain));
      if (!reasons.length) add(sharedHostingRuleReason(model, brand));
    }
    if (!reasons.length) add(model.ready
      ? "Hasil gabungan aturan model melewati batas risiko. Belum ada satu temuan yang cukup jelas untuk dijadikan alasan khusus."
      : "Halaman ditandai berisiko, tetapi rincian pemeriksaannya belum tersedia.");
  } else if (safe) {
    const guard = model.post_model_guard;
    add(guard && /^SELF_BRAND_/.test(guard.id || "")
      ? model.raw_verdict === "DANGEROUS"
        ? `Pemeriksaan identitas menunjukkan alamat ${guard.active_domain || domain} sesuai dengan situs yang ditemukan. Hasil ini mengubah keputusan menjadi tidak diblokir.`
        : `Hasil model berada di bawah batas risiko. Pemeriksaan identitas juga menunjukkan alamat ${guard.active_domain || domain} sesuai dengan situs yang ditemukan.`
      : model.ready
        ? "Hasil gabungan aturan model berada di bawah batas risiko. Ini bukan jaminan bahwa situs sepenuhnya aman."
        : "Tidak ditemukan indikasi phishing kuat, tetapi rincian model belum tersedia.");
  } else {
    add("Data pemeriksaan belum cukup untuk menyimpulkan keamanan halaman.");
  }
  const limitations = [];
  if (analysis.dom_error) limitations.push("Struktur halaman belum berhasil dibaca lengkap.");
  if (brand.brand_lookup_success === false || brand.brand_lookup_success === 0) limitations.push("Pencarian brand belum berhasil; identitas brand belum dapat dipastikan.");
  else if (Number(brand.brand_lookup_failed_queries) > 0) limitations.push("Sebagian pencarian brand gagal; informasi brand mungkin belum lengkap.");
  return {
    title: manual ? "Diblokir oleh daftar Anda" : dangerous ? "Terindikasi phishing" : safe ? "Tidak ditemukan indikasi phishing kuat" : "Pemeriksaan belum lengkap",
    summary: manual ? "Situs dihentikan sesuai pengaturan daftar blokir Anda." : dangerous ? "Halaman dihentikan karena hasil pemeriksaan menunjukkan risiko phishing." : safe ? "Tidak ditemukan indikasi phishing kuat pada pemeriksaan ini." : "Keamanan halaman belum dapat dipastikan.",
    domain, reasons: reasons.slice(0, 3),
    action: dangerous ? "Jangan masukkan kata sandi, OTP, atau data kartu sebelum memastikan identitas situs." : "Tetap periksa alamat situs sebelum memasukkan data pribadi.",
    limitation: limitations.join(" ")
  };
}

function brandExplanation(brand, pageUrl) {
  if (!brand || brand.unresolved_checks?.includes("dom_unavailable"))
    return "Identitas situs: belum dapat diperiksa.";
  const claim = brand.claimed_brand;
  const reference = brand.verified_reference_domain || claim?.official_domain;
  if (claim?.name && brand.official_domain_match === true && reference)
    return `Identitas situs: ${hostname(pageUrl)} cocok dengan domain resmi ${claim.name} (${reference}).`;
  if (claim?.name && brand.official_domain_match === false && reference)
    return `Identitas situs: halaman menampilkan ${claim.name}, tetapi domain yang dibuka berbeda dari domain resminya (${reference}). Hubungan resmi dengan domain ini belum dapat dipastikan.`;
  if (claim?.name)
    return `Identitas situs: nama ${claim.name} ditemukan, tetapi domain resminya belum dapat diverifikasi.`;
  if (brand.claimed_brand_status === "ambiguous")
    return "Identitas situs: beberapa nama merek ditemukan; identitas halaman belum dapat dipastikan.";
  return "Identitas situs: merek yang digunakan halaman belum dapat dipastikan.";
}

function domExplanation(dom) {
  if (!dom || dom.unresolved_checks?.includes("dom_unavailable") || !dom.observed_frame_count)
    return "Formulir: halaman belum dapat diperiksa.";
  const navigation = dom.navigation;
  if (navigation?.observed === true && navigation.destination_type === "official_provider")
    return "Login: pengalihan ke penyedia identitas resmi teramati; ini tidak membuktikan situs asal aman.";
  const relevant = (dom.forms || []).filter(form => form.relevant);
  const unverifiedCross = relevant.find(form => form.cross_domain === true && form.destination_verification === false);
  if (unverifiedCross)
    return `Formulir: tujuan pengiriman data akun adalah domain lain (${unverifiedCross.destination_registrable_domain || "tujuan tidak diketahui"}) yang belum terverifikasi.`;
  const otherCross = relevant.find(form => form.cross_domain === true);
  if (otherCross)
    return otherCross.destination_verification === true
      ? "Formulir: tujuan pengiriman data akun adalah domain lain yang terverifikasi."
      : "Formulir: tujuan pengiriman data akun adalah domain lain; hubungan resminya belum dapat dipastikan.";
  if (relevant.some(form => form.cross_domain === "unknown") || dom.form_cross_domain === "unknown")
    return "Formulir: tujuan pengiriman data akun belum dapat dipastikan.";
  if (relevant.length && dom.form_cross_domain === false)
    return "Formulir: tujuan yang tertera berada pada domain halaman ini; pengiriman aktual belum diamati.";
  if (dom.has_password_field === true || dom.has_sensitive_input === true)
    return "Formulir: halaman meminta data akun, tetapi tujuan pengirimannya belum dapat dipastikan.";
  if (dom.has_password_field === "unknown" || dom.has_sensitive_input === "unknown")
    return "Formulir: pemeriksaan data akun belum lengkap.";
  return "Formulir: tidak ditemukan permintaan data akun pada halaman yang diperiksa.";
}

function guardReason(guard) {
  if (guard.id === "BRAND_IDENTITY_MISMATCH_GUARD" || guard.id === "BRAND_LOOKALIKE_MODEL_GUARD") return guard.reason;
  if (guard.id === "CORROBORATED_BRAND_CLAIM_MISMATCH" || guard.id === "CORROBORATED_BRAND_TYPO") return guard.reason;
  if (guard.id === "BRAND_IMPERSONATION_GUARD" && guard.active_domain && guard.official_domain)
    return `Alamat ${guard.active_domain} menggunakan identitas ${guard.brand || "merek yang ditemukan"}, tetapi domain rujukannya adalah ${guard.official_domain}. Periksa alamat sebelum memasukkan data.`;
  if (guard.id === "REDIRECT_RISK_GUARD" && guard.original_domain && guard.final_domain)
    return guard.cross_domain_redirect
      ? `Alamat awal ${guard.original_domain} mengalihkan Anda ke ${guard.final_domain}. Perubahan tujuan ini ikut menyebabkan halaman diblokir; periksa alamat akhirnya.`
      : `Alamat awal ${guard.original_domain} menyerupai nama layanan lain. Periksa apakah alamat itu benar milik layanan yang dituju.`;
  if (guard.id === "SHARED_HOSTING_BRAND_GUARD" && guard.original_domain)
    return `Alamat ${guard.original_domain} berada pada layanan hosting publik dan memuat nama layanan populer. Periksa apakah halaman itu benar milik layanan yang disebut.`;
  return "Pemeriksaan tambahan menemukan pola risiko yang memengaruhi keputusan pemblokiran. Periksa alamat situs sebelum melanjutkan.";
}
function riskRules(model) {
  return (model.fired_rules || []).filter(rule => Number(rule.coefficient) > 0);
}
function observed(rule, feature, operator) {
  return (rule.conditions || []).some(c => c.feature === feature && c.passed === true &&
    (!operator || c.operator === operator) && typeof c.value === "number" && Number.isFinite(c.value));
}
function brandRuleReason(model, brand, url, domain) {
  if (!brand.brand_found || !brand.brand_top_candidate_domain ||
      !(brand.brand_matches_page === false || brand.brand_matches_page === 0)) return null;
  const official = brand.brand_top_candidate_domain, label = official.split(".")[0]?.toLowerCase();
  if (!label || !String(domain).toLowerCase().split(/[^a-z0-9]+/).includes(label)) return null;
  if (!riskRules(model).some(rule => observed(rule, "brand_matches_page", "<="))) return null;
  return `Alamat ${url.final_registrable_domain || domain} memuat nama ${brand.brand_top_candidate_name || label}, tetapi domain rujukan yang ditemukan adalah ${official}. Ketidaksesuaian ini ikut menaikkan risiko; periksa alamat situs.`;
}
function ageRuleReason(model, rdap, url, domain) {
  for (const [feature, available, ageDomain] of [
    ["page_domain_age_days", rdap.final_rdap_available, url.final_registrable_domain || domain],
    ["source_domain_age_days", rdap.original_rdap_available, url.original_registrable_domain || domain]
  ]) {
    if (!available) continue;
    const age = Number(rdap[feature]);
    if (!Number.isFinite(age) || age < 0 || age > 180) continue;
    const used = riskRules(model).some(rule => (rule.conditions || []).some(c =>
      c.feature === feature && c.passed === true && (c.operator === "<=" || c.operator === "<") &&
      typeof c.value === "number" && Number.isFinite(c.value) && Math.abs(c.value - age) < 1));
    if (used) return `Data pendaftaran menunjukkan domain ${ageDomain} berumur sekitar ${Math.round(age)} hari. Umur domain ini ikut menaikkan risiko dalam aturan yang aktif.`;
  }
  return null;
}
function sharedHostingRuleReason(model, brand) {
  if (!brand.brand_found) return null;
  if (!riskRules(model).some(rule => (rule.conditions || []).some(c =>
      c.feature === "source_uses_shared_hosting_domain" && c.passed === true && c.value === 1) &&
      observed(rule, "brand_search_score") && observed(rule, "brand_quality_score"))) return null;
  return `Alamat berada pada layanan hosting bersama dan menunjukkan keterkaitan dengan ${brand.brand_top_candidate_name || "suatu merek"}. Kombinasi ini ikut menaikkan risiko; periksa identitas situsnya.`;
}
function hostname(value) {
  try { return new URL(value).hostname; } catch { return "domain halaman"; }
}
