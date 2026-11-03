# Diagnosis uji XGBoost dan daftar legitimate baru

## Mengapa hasil legitimate sebelumnya 79,07%?

Pada 100 URL legitimate sebelumnya, model XGBoost 18 fitur hanya dapat
memprediksi 86 URL karena 14 domain tidak memberikan umur registrasi melalui
RDAP. Dari 86 yang diprediksi, 68 benar dan 18 salah (68/86 = 79,07%).

Dalam 18 kesalahan itu, 10 URL menggunakan HTTP. Di antara 86 URL yang
dievaluasi, hanya 12 URL menggunakan HTTP; dengan demikian 10/12 URL HTTP
legitimate dinilai phishing. Pada data latih, HTTP terdapat pada 3.471/14.934
phishing (23,24%) tetapi hanya 348/14.934 legitimate (2,33%). Ini memberi
model asosiasi yang kuat antara HTTP dan label phishing. Kontribusi fitur
XGBoost untuk 18 kasus salah juga menunjukkan `has_https_scheme` sebagai
pendorong skor risiko terbesar secara rata-rata. Kontribusi ini adalah
penjelasan perilaku model pada kasus tersebut, bukan bukti kausal.

Selain itu, setidaknya dua URL berlabel legitimate dalam daftar lama kini
menampilkan halaman bawaan hosting/server. Label halaman aktualnya perlu
ditinjau, karena respons HTTP 200 tidak membuktikan layanan aslinya masih
beroperasi. Umur domain membantu menurunkan skor risiko pada sebagian situs,
tetapi tidak selalu cukup untuk mengimbangi sinyal lain.

Ambang 0,38 tetap ambang yang dipilih dari validasi lama. Mengubahnya berdasarkan
100 URL ini akan membuat pengujian berikutnya bias. Hasil 300 phishing juga
belum merupakan validasi eksternal penuh karena sebagian situs/URL tumpang
tindih dengan data model dan label halamannya belum diverifikasi live.

## Kecukupan 18 fitur

Untuk tahap pengujian URL saja, 18 fitur cukup sebagai konfigurasi awal yang
dibekukan. Menambah fitur sekarang tanpa pola kesalahan yang konsisten dapat
menambah kompleksitas tanpa memperbaiki generalisasi. Satu dari 18 fitur,
`has_ip_host`, bernilai nol pada seluruh 29.868 baris data pelatihan, sehingga
model tidak memiliki contoh untuk mempelajari pengaruhnya. Perbaikan pertama
adalah memperluas contoh legitimate HTTP yang terverifikasi, meninjau mutu
label/halaman, serta memastikan umur domain dikumpulkan dengan cara seragam.

## Daftar uji legitimate baru

`C:\Users\USER\Downloads\legitimate_baru_300_xgboost_terverifikasi_31okt.txt`
berisi 300 URL dari 300 situs berbeda. Audit rinci ada di
`persiapan_300_legitimate_xgboost/audit_300_terverifikasi.csv`.

- Semua 300 URL mengembalikan HTML 200 dan memiliki judul halaman pada saat
  penyusunan; halaman error/challenge yang tampak dari judul disaring.
- Ketiga ratus domain mempunyai umur dari RDAP; 276 URL HTTPS dan 24 HTTP.
- Tidak ada situs yang tumpang tindih dengan korpus gabungan, partisi model,
  atau daftar 100 legitimate sebelumnya.
- Sumber identitas organisasi dan situs resminya adalah catatan ROR. Halaman
  masih dapat berubah atau berpindah; pemeriksaan browser saat uji tetap perlu.

Prediksi XGBoost belum dijalankan pada 300 URL baru agar daftar ini tetap
tersedia sebagai uji baru yang tidak dipakai menyetel model atau ambang.
