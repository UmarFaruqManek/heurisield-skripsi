# Audit 29 hasil phishing yang dinyatakan SAFE (31 Oktober 2026)

Sumber: `browser_live_raw_analysis.jsonl` dan `browser_live_incorrect.csv` pada direktori ini. Laporan ini memeriksa hasil yang **berhasil dianalisis**, bukan halaman yang gagal dibuka. Berkas `audit_29_kesalahan_brand_20261031.csv` memuat bukti dan interpretasi untuk setiap indeks URL.

## Angka awal

- 300 URL pada daftar; 146 analisis lengkap; 117 benar dan 29 salah menurut label feed (80,14% dari yang dianalisis).
- 154 tanpa analisis lengkap: 127 HTTP error (120 di antaranya HTTP 403) dan 27 kondisi lain. Ini bukan prediksi model.
- Dari 29 yang salah, 17 memiliki kandidat brand pada extractor lama, 12 tidak. Sebanyak 15 berstatus identitas `unknown`; hanya satu mendapat guard, yaitu guard yang justru mempertahankan SAFE untuk kandidat domain sendiri.

## Kelompok bukti yang ditemukan

| Pola | Indeks | Jumlah | Penjelasan ringkas |
|---|---|---:|---|
| Brand pada alamat dan judul | 79, 177, 184, 239 | 4 | Roblox terdeteksi pada judul serta alamat yang sangat mirip. Aturan lama memerlukan formulir akun; pada halaman ini tidak ada formulir yang teramati. |
| Konten pengguna di platform | 32, 33, 127, 155, 207, 226, 259 | 7 | API sering memilih identitas platform (`bio.site`, `surge.sh`, dan lain-lain), yang tidak membuktikan identitas halaman penggunanya. |
| Brand pada judul dengan formulir | 120, 245, 246, 283 | 4 | Judul menyebut Metanet, SG, atau WeTransfer; pada domain berbeda ditemukan field kata sandi. Judul saja masih berisiko salah menandai integrasi resmi seperti webmail perguruan tinggi. Indeks 245 dan 246 berakhir di halaman sama. |
| Halaman unduh/wallet | 133, 134, 154, 173, 181 | 5 | Judul halaman berbahasa Mandarin berkaitan dengan unduhan TP Wallet; lookup brand pada subdomain pendek memilih organisasi yang tidak relevan. Belum ada bukti arsip bahwa halaman mengunduh berkas berbahaya. |
| Brand pada judul tanpa bukti kedua | 13, 178, 179, 249, 289 | 5 | Halaman menyebut AR24, Shopee, TikTok, atau Meta, tetapi formulir akun tidak teramati. Usia domain muda saja bukan bukti phishing. |
| Label/kondisi perlu diverifikasi | 5, 35, 223, 287 | 4 | Halaman yang terlihat tidak cukup menjelaskan label feed: ada portal domain sendiri, PDF viewer, eChallan, dan DPD pada hosting lain. Indeks 287 mendekati ambang model (0,766), tetapi menaikkan risiko semua halaman sejenis dapat menambah false positive. |

## Perubahan dan pemutaran ulang

- Analyzer sekarang mempertahankan kandidat brand alternatif dari judul sebagai bukti audit terpisah dari brand pemilik domain. Nama platform hosting tidak lagi diperlakukan sebagai bukti identitas konten pengguna.
- Aturan tambahan untuk nama brand yang sangat mirip mensyaratkan kandidat API, nama brand pada judul, dan skor mentah RuleFit minimal 0,40 bila tidak ada formulir akun. Domain dengan label sama pada TLD berbeda tidak diblokir hanya karena ada formulir.
- Pemutaran ulang keputusan dari arsip: **4 indeks (79, 177, 184, 239)** berubah dari SAFE ke DANGEROUS; pada **490 URL legitimate yang sebelumnya dievaluasi**, tidak ada keputusan SAFE yang berubah dalam replay. Jika label feed diasumsikan benar dan kondisi halaman tetap sama, hasil phishing menjadi **121/146 = 82,88%**. Angka ini estimasi pengembangan pada data yang sama, **bukan hasil live atau uji eksternal independen**.
- Dua puluh lima indeks lain tetap SAFE dalam replay. Saya tidak menambahkan aturan hanya berdasarkan judul, umur domain, atau status API kandidat karena arsip belum cukup untuk membedakan phishing dari halaman legitimate serupa.

## Batas bukti

Arsip memuat URL, judul, fitur DOM, respons brand, dan hasil model, tetapi tidak menyimpan HTML lengkap atau bukti kepemilikan domain. Label feed dapat berubah ketika halaman berubah, dan beberapa URL mengarah ke halaman akhir yang sama. Pemutaran ulang menggunakan hasil ekstraksi saat pengujian; akurasi versi 5.0.24 perlu diukur dengan pengujian live baru yang dijalankan pengguna. Arsip 490 legitimate berasal dari versi sebelumnya, sehingga angka nol perubahan adalah pemeriksaan regresi terbatas, bukan jaminan tidak ada false positive pada data baru.
