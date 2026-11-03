# Panduan proyek HeuriShield untuk AI lain

Dokumen ini menjelaskan **implementasi yang sedang digunakan** di repository ini. Bacalah bersama kode sebelum mengusulkan perubahan. Fokus pengembangan saat ini adalah extension `extension/HeuriShield-URL18-XGBoost/` versi **0.2.15**, bukan extension RuleFit60 yang disimpan sebagai pembanding di `arsip/pembanding_rulefit60/`.

Semua jalur `src/...` dan `tests/...` di bawah ini dihitung dari folder extension utama tersebut.

## Tujuan dan ruang lingkup

HeuriShield adalah extension browser berbasis Chromium Manifest V3 untuk membantu mengenali halaman phishing. Keputusan awal berasal dari model XGBoost atas **18 fitur URL**. Bukti dari struktur halaman (DOM) dan identitas brand kemudian diperiksa dengan aturan korelasi untuk menilai apakah keputusan awal perlu dikoreksi. Hasilnya tampil di panel extension atau halaman peringatan; pengguna juga memiliki allowlist dan blocklist.

Model URL memprediksi risiko dari pola alamat, bukan membuktikan niat pemilik situs. Kecocokan nama brand, keberadaan formulir login, atau usia domain juga bukan bukti tunggal bahwa halaman aman maupun berbahaya.

## Alur saat sebuah halaman dibuka

1. `src/background/service-worker.js` menangkap navigasi dan menyimpan URL awal serta URL halaman akhir. Halaman penyedia OAuth yang dikenali dianalisis berdasarkan URL penyedianya sendiri; parameter `redirect_uri` atau `app_domain` tidak dianggap sebagai domain halaman yang sedang dibuka.
2. URL Analyzer menghitung 17 fitur dari teks URL. Fitur ke-18, `domain_age_days`, diambil dari tanggal registrasi domain melalui RDAP/API. Jika tanggal tidak ditemukan, nilainya **`null`/unknown**, bukan diisi angka buatan.
3. Model XGBoost yang sudah diekspor ke `src/model/xgboost-url18.json` menghasilkan `probability_phishing`. Jika nilainya **≥ 0,35**, prediksi awal adalah phishing (`DANGEROUS`); jika di bawahnya, legitimate (`SAFE`). Nilai umur yang hilang mengikuti cabang *missing value* model.
4. Content script `src/content/dom-brand-observer.js` mengamati metadata DOM, termasuk formulir, kolom sensitif, tombol login, judul, heading, dan identitas halaman. Pemantauan perubahan DOM juga menangani sebagian halaman dinamis/SPA. Isi kata sandi dan OTP tidak dibaca sebagai nilai fitur.
5. Brand Analyzer mengambil kandidat dari label subdomain dan nama domain serta dari judul/heading/logo utama halaman. Pencarian memakai layanan brand yang sudah terpasang, lalu membandingkan domain kandidat dengan domain yang sedang dibuka. Kandidat yang ditemukan oleh API belum tentu merupakan bukti kepemilikan resmi.
6. Correlation Rule Engine menggabungkan temuan DOM dan brand. Decision policy dapat menaikkan hasil URL yang semula `SAFE` menjadi `DANGEROUS` jika bukti peniruan kuat, atau membatalkan sebagian hasil `DANGEROUS` pada keadaan yang sangat terbatas dengan bukti independen. Hasil akhir, bukti, alasan, serta fitur dicatat untuk audit.
7. Jika hasil akhir `DANGEROUS`, extension mengarahkan tab ke halaman peringatan. Allowlist dan blocklist pengguna diproses oleh alur tersendiri dan dapat mendahului keputusan model.

Alur singkat: `URL + umur domain → XGBoost → DOM + brand → aturan korelasi → kebijakan keputusan → tampilan dan riwayat`.

## Fitur URL yang digunakan model

Urutan resmi ada di `src/model/feature-contract-18.json`. Jangan mengubah nama, urutan, atau cara menghitung fitur pada extension tanpa menyelaraskannya dengan data latih dan model.

| Fitur | Makna |
| --- | --- |
| `url_length` | Panjang seluruh URL. |
| `hostname_length` | Panjang hostname. |
| `path_length` | Panjang path. |
| `query_length` | Panjang bagian query. |
| `subdomain_count` | Jumlah label subdomain. |
| `path_depth` | Banyak segmen path. |
| `dot_count` | Jumlah titik pada hostname. |
| `hyphen_count` | Jumlah tanda hubung pada hostname. |
| `digit_ratio` | Proporsi digit pada hostname. |
| `special_char_count` | Banyak karakter selain huruf/angka pada path dan query. |
| `has_at_symbol` | Penanda keberadaan `@` di URL. |
| `has_ip_host` | Penanda hostname berupa alamat IP. |
| `has_https_scheme` | Penanda skema HTTPS. |
| `hostname_entropy` | Entropi karakter hostname. |
| `sensitive_token_count` | Jumlah token seperti `login`, `verify`, atau `password` pada path/query. |
| `url_entropy` | Entropi karakter seluruh URL. |
| `path_hyphen_count` | Jumlah tanda hubung pada path. |
| `domain_age_days` | Umur domain dari tanggal registrasi yang berhasil diamati. |

Definisi teknis 17 fitur leksikal ada di `src/analyzer/url/url18-features.js`; pencarian umur ada di `src/analyzer/domain/url18-age.js`; prediksi ada di `src/model/xgboost-engine.js`.

## DOM, brand, dan aturan

**DOM Analyzer** menyimpan lima temuan utama: `has_password_field`, `has_sensitive_input`, `form_cross_domain`, `login_button_detected`, dan `login_redirect_detected`. Ia juga menyimpan rincian formulir, tombol, tujuan pengiriman, navigasi, serta status frame yang tidak terbaca. Nilai `unknown` berarti bukti belum tersedia; jangan menafsirkannya sebagai `false`. Formulir yang mengirim ke domain yang sama **tidak otomatis aman**.

**Brand Analyzer** mencari token dari hostname dan halaman, termasuk label subdomain yang bermakna. Contoh, pada `gemini.google.com`, `gemini` dan `google` dapat menjadi kandidat pencarian; label umum seperti `app` dikecualikan. Pemisahan domain mempertimbangkan public suffix, termasuk suffix bertingkat seperti `ac.id` dan domain penyedia hosting. Clearbit dicoba untuk kandidat, Brandfetch tetap dicoba untuk kandidat dan informasi verifikasi; API domain `brnad-heuri.vercel.app` menjadi cadangan untuk identitas berdasarkan domain yang dibuka. Temuan seperti `claimed_brand_status`, `official_domain_match`, `brand_domain_mismatch`, dan `verified_reference_domain` dipakai sebagai bukti, dengan status tidak diketahui tetap terpisah dari ketidakcocokan. Nama brand di judul halaman dapat disalin oleh penyerang, sehingga tidak cukup sebagai bukti resmi.

**Correlation Rule Engine** ada di `src/analyzer/correlation/evidence-rules.js` dengan aturan `R01`–`R10`. Tiap aturan berstatus `matched`, `not_matched`, atau `undetermined`. `R03`, `R07`, dan `R10` dapat menghasilkan bukti kuat peniruan kredensial; `R09` dapat menghasilkan bukti kuat peniruan brand pada hostname; `R06` mengenali konteks OAuth resmi tanpa otomatis mengubah skor URL. Aturan ini **tidak mempunyai bobot numerik yang dijumlahkan dengan skor model**. Kebijakan keputusan ada di `src/analyzer/correlation/decision-policy.js`.

Koreksi dari phishing ke legitimate sengaja sempit. Contohnya adalah halaman penyedia OAuth dengan host HTTPS dan referensi resmi yang cocok, atau halaman login pada domain resmi dengan formulir satu origin dan bukti independen lain. Kecocokan kandidat API saja, umur domain yang panjang saja, atau kata brand di halaman saja tidak cukup untuk membuka blokir.

## API dan sumber data yang terpasang

| Keperluan | Urutan/sumber pada implementasi aktif |
| --- | --- |
| Umur domain | Bootstrap RDAP IANA → RDAP registri → Beryl WHOIS → Dun WHOIS → Who-Dat. Jika seluruhnya gagal, umur `unknown`. |
| Kandidat brand | Clearbit Autocomplete → Brandfetch Search; keduanya diperiksa dalam alur pencarian token. API `brnad-heuri.vercel.app/api/v1/domain/` dipakai sebagai cadangan pencarian berdasarkan domain. |
| Pemisahan domain | Library `tldts` dan referensi suffix yang disertakan dalam extension. |
| Model | JSON XGBoost lokal di dalam extension; tidak memerlukan server model. |

Ketersediaan API dapat berubah atau terkena batas akses. Respons yang kosong dan permintaan yang gagal harus dicatat berbeda. Tidak ada layanan localhost yang wajib dijalankan untuk memakai extension utama.

## Riwayat dan pengujian

Extension menyimpan analisis tab, riwayat URL, dan fitur di penyimpanan browser. Pencatatan dataset `evaluationDataset` menyimpan URL yang dibersihkan, 18 nilai fitur, serta **label hasil prediksi**, bukan label aktual yang telah diverifikasi; kapasitasnya 2.000 catatan. Pencatatan file JSON lewat halaman Pencatatan memerlukan pengguna memilih/memberi izin pada file dan membiarkan tab tersebut terbuka untuk sinkronisasi. **Perhatian:** halaman Pencatatan saat ini masih membaca kontrak 60 fitur lama, sedangkan kolektor extension aktif menyimpan 18 fitur. Karena ketidaksesuaian ini, jangan mengklaim sinkronisasi ke `hasil-ekstraksi.json` sudah valid untuk extension URL18 tanpa menguji dan memperbaikinya.

Penguji live terpisah berada di `skrip/evaluasi/evaluate-extension-browser-live.py`. Laporan per URL (`browser_live_analysis.json`) mencakup fitur, bukti DOM/brand, skor, aturan, dan hasil akhir ketika analisis lengkap. `hasil/` menyimpan arsip uji yang dipublikasikan; hasil baru di `hasil_baru/` dan indeks SQLite lokal dapat berada di luar Git. Untuk mengukur kinerja, laporkan **jumlah yang berhasil dianalisis, jumlah benar/salah pada kelompok tersebut, dan jumlah tanpa analisis**. Jangan menghitung halaman warning yang terlihat sebagai prediksi model terverifikasi bila rekaman analisisnya belum lengkap. URL yang dipakai mengubah model/aturan adalah data pengembangan, bukan lagi uji independen.

## Lokasi penting dan cara melanjutkan

- Extension siap muat: `extension/HeuriShield-URL18-XGBoost/` → pilih folder ini melalui **Load unpacked** pada browser Chromium.
- Manifest dan alur utama: `manifest.json`, `src/background/service-worker.js`.
- Model dan kontrak fitur: `src/model/xgboost-url18.json`, `src/model/feature-contract-18.json`.
- Ekstraksi URL: `src/analyzer/url/url18-features.js`; umur domain: `src/analyzer/domain/url18-age.js`.
- Pengamatan halaman: `src/content/dom-brand-observer.js`; analisis: `src/analyzer/dom/dom-evidence.js` dan `src/analyzer/brand/brand-evidence.js`.
- Korelasi dan keputusan: `src/analyzer/correlation/evidence-rules.js`, `src/analyzer/correlation/decision-policy.js`.
- Alasan UI: `src/shared/analysis-explanation.js`; uji kode: `tests/`.
- RuleFit60 lama: `arsip/pembanding_rulefit60/`, hanya sebagai pembanding penelitian.

Saat AI lain diminta memperbaiki sistem, periksa dahulu versi extension dan rekaman kasus per URL, tentukan apakah kesalahan muncul dari ekstraksi, respons API, model, bukti DOM/brand, kebijakan keputusan, atau evaluator. Uji perubahan pada arsip **legitimate dan phishing**, lalu minta pengguna menjalankan pengujian live pada data baru. Jangan menyimpulkan peningkatan akurasi dari pemutaran ulang data yang sama saja.
