# HeuriShield Skripsi

Repository penelitian deteksi phishing berbasis **18 fitur URL dengan XGBoost**, dilengkapi pemeriksaan DOM, identitas brand, dan aturan korelasi. Versi extension saat ini adalah **0.2.16** dengan ambang URL **0,35**.

## Langsung menggunakan extension

Kandidat eksperimen terbaru juga tersedia di **`extension/HeuriShield-URL17-XGBoost`**, versi **0.3.2**: model memakai 17 fitur teks URL dengan threshold 0,45; umur domain diperiksa terpisah. Pencarian brand memakai domain terlebih dahulu (Clearbit → Brandfetch → API domain HeuriShield), kemudian token ketika diperlukan. Pilih folder kandidat tersebut melalui **Load unpacked** untuk menguji URL17; folder URL18 di bawah tetap tersedia sebagai pembanding. Lihat [audit 400 legitimate dan batas replay](docs/AUDIT_URL17_DOMAIN_FIRST_04NOV2026.md).

1. Clone atau unduh repository ini.
2. Buka `chrome://extensions` atau halaman extension browser Chromium lain, aktifkan **Developer mode**, lalu pilih **Load unpacked**.
3. Pilih folder **`extension/HeuriShield-URL18-XGBoost`** di dalam repository ini. `manifest.json`, model, aset, dan bundle content script sudah tersedia; tidak ada server atau proses build yang wajib dijalankan.

Alurnya: URL dan umur domain → skor XGBoost → pemeriksaan DOM dan brand → aturan korelasi → keputusan serta alasan pada panel/halaman peringatan. URL tanpa umur domain memakai cabang nilai hilang pada model. Halaman OAuth penyedia resmi diperiksa pada domain penyedianya; domain aplikasi tujuan tidak otomatis dianggap aman. Daftar izin/blokir pengguna tersimpan lokal pada browser.

## Isi repository

| Lokasi | Isi |
|---|---|
| `extension/HeuriShield-URL18-XGBoost/` | Extension utama siap dimuat, model, dan uji kode. |
| `data/dataset/` | Dataset URL, label, umur domain, dan fitur untuk pengembangan model. |
| `data/input_uji/` | Daftar dan persiapan URL uji. Parameter autentikasi disamarkan pada salinan publik. |
| `skrip/` | Ekstraksi fitur, pelatihan, audit, dan uji kode penelitian. |
| `skrip/evaluasi/` | Evaluator live, penyatuan laporan, pemutaran ulang, dan pembentukan indeks SQLite lokal. |
| `hasil/` | Model pembanding, hasil eksperimen, laporan live per URL, audit, dan ringkasan. |
| `arsip/pembanding_rulefit60/` | Extension RuleFit60 lama beserta riwayat pengujiannya. |
| `docs/` | Catatan metode, penggabungan data, dan tinjauan referensi. |

Untuk memahami cara kerja versi aktif sebelum menelaah kode, baca [Panduan proyek untuk AI lain](docs/PANDUAN_PROYEK_UNTUK_AI.md).

Arsip `browser_live_analysis.json` adalah sumber riwayat per URL. Database SQLite lokal tidak disertakan karena merupakan indeks turunan berukuran lebih dari 100 MiB; indeks dapat dibuat kembali dari laporan dengan:

```powershell
python .\skrip\evaluasi\rebuild_history_db.py
```

Untuk menjalankan skrip penelitian, pasang dependensi dengan `python -m pip install -r requirements-research.txt`. Sebagian skrip persiapan historis masih memerlukan sumber asli di luar repository; extension utama dan laporan yang telah diarsipkan tidak memerlukannya. Untuk uji live baru, jalankan pula `python -m playwright install chromium`, lalu gunakan evaluator dengan `--isolated-per-url`. Pengujian live membuka URL yang diberikan; lakukan dalam lingkungan uji terpisah. Contoh:

```powershell
python .\skrip\evaluasi\evaluate-extension-browser-live.py --extension-dir .\extension\HeuriShield-URL18-XGBoost --input .\data\input_uji\daftar_terbaru\phishing_fresh_300_03nov2026_url18.txt --label phishing --out-dir .\hasil_baru\phishing --isolated-per-url --checkpoint-every 25
```

## Membaca hasil

Laporkan **akurasi pada URL yang berhasil dianalisis** bersama **cakupan analisis** dan jumlah tanpa analisis. Contoh uji terbaru: legitimate Indonesia 156/190 benar (82,11%, cakupan 95%); legitimate beragam 284/291 (97,59%, cakupan 97%); phishing 131/143 (91,61%, cakupan 47,67%). Perbedaan kelompok dan cakupan yang rendah membatasi generalisasi angka gabungan. URL yang dipakai untuk menyesuaikan model atau aturan adalah data pengembangan, bukan uji independen baru.

## Data dan privasi

Salinan publik mempertahankan label, fitur, skor, keputusan, dan status pengujian. Nilai parameter autentikasi dalam URL serta alamat email telah disamarkan. Karena itu, beberapa URL pada salinan publik tidak identik dengan URL mentah saat pengujian; gunakan fitur dan snapshot model yang tersimpan untuk menelaah keputusan historis. Pada arsip RuleFit60, berkas `browser_live_raw_analysis.jsonl` dan checkpoint sementara tidak disertakan karena isi per URL sudah ada pada `browser_live_analysis.json` atau `browser_live_rows.csv`. Workbook `.xlsx` duplikat, berkas inspeksi sementara, arsip ROR pihak ketiga, cache, dan indeks SQLite turunan tidak disertakan. Simpan data mentah asli secara privat.
