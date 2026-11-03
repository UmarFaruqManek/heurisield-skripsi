# HeuriShield URL18 XGBoost

Extension Manifest V3 versi **0.2.16**. Folder ini siap dipilih lewat **Load unpacked** pada browser Chromium; bundle content script dan model sudah tersedia.

URL Analyzer mengekstrak 18 fitur dan menghitung probabilitas phishing dengan XGBoost pada ambang **0,35**. Brand Analyzer mencari kandidat lewat layanan yang sudah terhubung, sedangkan DOM Analyzer memeriksa identitas halaman dan perilaku formulir tanpa menyimpan kata sandi/OTP. Aturan korelasi menggabungkan bukti, termasuk peniruan brand dan konteks OAuth. Halaman penyedia OAuth resmi hanya dikenali bila host, rujukan brand, bentuk permintaan, dan bukti halaman cocok; situs aplikasi tujuan tetap dinilai terpisah.

Data dan laporan pengujian ada pada [README repository](../../README.md). Untuk pemeriksaan kode lokal, jalankan berkas dalam `tests/` menggunakan Node.js dan Python/Playwright sesuai jenis berkas. Pengujian live yang direkam dilakukan menggunakan evaluator di `../../skrip/evaluasi/`.
