# Audit evaluator pengujian phishing yang dihentikan — 31 Oktober 2026

Batch dihentikan setelah 956 dari 1.448 URL. Arsip mentah mencatat 142
analisis lengkap (123 putusan phishing, 19 aman), 482 halaman peringatan
yang terlihat tanpa hasil model terverifikasi, dan 332 tanpa analisis valid.
Ketepatan bersyarat pada 142 hasil lengkap ialah 86,62%; cakupan hanya
14,85%. Ini bukan ringkasan pengujian akhir atau estimasi yang dapat
dibandingkan langsung dengan batch legitimate (490/500 teranalisis).

## Kesalahan pencocokan URL evaluator

Browser menormalisasi `https://contoh.com` menjadi `https://contoh.com/`.
Evaluator sebelumnya hanya menghapus fragmen, sehingga pemeriksaan
`valid_current_analysis` dapat menolak hasil situs yang sama sebagai URL
berbeda. Dari 482 catatan `warning_page_observed`, hanya 1 input cocok
persis dengan URL respons HTTP sebelum normalisasi; setelah normalisasi,
482 cocok. Dari 332 `no_valid_analysis`, kecocokan tersebut naik dari
2 menjadi 313. Ini bukti masalah pencocokan URL, tetapi belum membuktikan
bahwa semua hasil akan pulih: syarat tab, waktu, dan model lengkap juga
harus terpenuhi.

Perbaikan dilakukan pada `D:\Deployment Extension\Skrip\evaluate-extension-browser-live.py`
di fungsi `comparable_url`: URL HTTP(S) dengan path kosong diberi path `/`
untuk tujuan perbandingan. Dua uji regresi offline lulus. Tidak ada
pengujian live baru yang dijalankan untuk memverifikasi dampaknya.

## Implikasi untuk perbaikan klasifikasi

Pada 57 kesalahan legitimate sebelumnya, 37 berasal dari putusan RuleFit
dan 20 memiliki guard brand aktif. Dari 19 putusan aman pada batch phishing
ini, beberapa URL berakhir pada halaman resmi atau tautan kedaluwarsa,
sehingga label harus diperiksa sebelum dipakai sebagai contoh kesalahan.
Kandidat pembatasan guard brand yang memperbaiki 13 kasus legitimate juga
akan mengubah satu hasil phishing yang sesuai label feed (indeks 436) menjadi
aman; identitas situs itu belum diverifikasi. Kandidat belum layak dirilis.

Langkah selanjutnya: verifikasi label dan keadaan halaman; perbaiki evaluator
dan ukur ulang cakupannya pada batch kecil yang dijalankan pengguna; baru
setelah itu lakukan replay serta pelatihan/penyetelan dengan data
pengembangan terpisah dari uji akhir.
