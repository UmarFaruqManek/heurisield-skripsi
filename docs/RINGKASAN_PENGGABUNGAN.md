# Penggabungan URL, label, dan umur domain

Hasil snapshot: 31 Oktober 2026. Tidak ada situs atau API yang diakses ulang dan tidak ada model yang dilatih.

## Hasil utama

| Ukuran | Jumlah |
|---|---:|
| URL unik dengan label tidak bertentangan | **614.818** |
| Label legitimate | 275.454 |
| Label phishing | 339.364 |
| Ada angka umur domain yang tersimpan | 34.149 |
| Umur domain kosong | 580.669 |
| URL konflik label, dipisah dari gabungan | 7 |

CSV utama `gabungan_url_label_umur.csv` mempunyai tepat tiga kolom: `url,label,domain_age_days`.

| Kelompok sumber setelah deduplikasi | URL unik | Legitimate | Phishing | Umur tersedia |
|---|---:|---:|---:|---:|
| Pernah ada di data internal/crawl/pengujian live | 52.961 | 26.953 | 26.008 | 34.149 |
| Hanya terdapat pada dataset eksternal yang diunduh | 561.857 | 248.501 | 313.356 | 0 |

Kelompok dapat tumpang tindih sebelum deduplikasi. Sebanyak 9.447 URL dalam gabungan pernah tercatat pada hasil pengujian live; 8.026 di antaranya hanya ditemukan pada kelompok uji live, tidak pada korpus internal atau eksternal yang dipilih. Semua baris dan sumber asalnya dapat dilihat dalam `audit_gabungan_url.csv`. Angka *dengan umur* berarti angka pernah tersimpan, **bukan** bahwa semua umur dihitung untuk tanggal acuan yang sama.

## Sumber yang disatukan

- Arsip mentah hasil crawl lama dengan URL dan label; dataset eksperimen 32 fitur versi umur teramati; data tambahan pelatihan RuleFit60 yang masih menyimpan URL; hasil crawl legitimate yang sukses.
- Berkas `browser_live_rows.csv` hasil akhir pengujian (bukan `.partial`, hasil replay, atau salinan `gabungan`). Yang dipakai adalah `expected_label`, bukan `actual_verdict` atau prediksi model. URL yang tidak dianalisis tetap muncul dalam gabungan untuk inventaris, dengan statusnya pada audit.
- Dataset eksternal: PhiUSIIL, PhishBD, dataset2, phishDB, dataset_B_2020, serta arsip `verified_online` yang berstatus terverifikasi. Pemetaan angka label PhiUSIIL, PhishBD, dan dataset2 diperiksa terhadap berkas pemisahan phishing/legitimate yang telah ada di Downloads. Sumber eksternal ini belum dianggap terverifikasi ulang untuk kondisi live sekarang.
- `history-extract/hasil-ekstraksi.json` hanya dipakai untuk melengkapi umur URL yang **sudah memiliki label dari sumber lain**. Label di file tersebut adalah prediksi extension, sehingga tidak dijadikan label aktual.

## Batas penting sebelum pelatihan

1. **Gabungan ini inventaris, belum data latih siap pakai.** URL dan domain dari pengujian lama bercampur dengan data latih dan hasil penyetelan. Pisahkan menurut domain dan waktu sebelum membangun pengujian independen.
2. Mayoritas sumber eksternal tidak memiliki umur domain. Jangan mengisinya berdasarkan label atau menganggap kosong berarti umur muda.
3. Angka umur berasal dari waktu pengamatan yang berbeda. Untuk fitur model final, gunakan tanggal registrasi dan tanggal acuan yang konsisten bila tersedia. Pada subdomain hosting publik, umur domain platform juga tidak sama dengan umur halaman.
4. Sebagian URL pengujian menerima HTTP error atau tidak memperoleh analisis. Status ini terlihat dalam kolom `test_statuses` pada audit dan perlu disaring sebelum menjadikannya contoh pelatihan.
5. Tujuh URL dengan label berbeda antar-sumber tersimpan dalam `konflik_label_url.csv` untuk pemeriksaan manual; tidak ada label yang dipilih secara otomatis.
6. Data latih RuleFit60 yang sudah diproses dan kehilangan kolom URL tidak dapat direkonstruksi per baris secara pasti. Hanya sumber mentah/riwayat yang masih menyimpan URL yang dapat digabungkan.

## Berkas

- `gabungan_url_label_umur.csv`: tiga kolom sesuai permintaan.
- `audit_gabungan_url.csv`: sumber, kelompok, umur terpilih, dan status pengujian per URL.
- `konflik_label_url.csv`: URL yang labelnya bertentangan.
- `ringkasan_gabungan.json`: angka per sumber yang dapat diaudit.
- `gabung_url_label_umur.py`: skrip untuk membangun ulang snapshot ini dari berkas asal.

Langkah berikutnya, bila rancangan data sudah disetujui: pilih subkorpus dengan label dan status yang layak, bekukan tanggal acuan umur, kemudian buat skrip ekstraksi 15 fitur URL dari kolom `url` dengan definisi yang sama untuk dataset dan extension.
