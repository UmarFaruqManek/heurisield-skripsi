# Uji offline daftar baru: 300 phishing dan 100 legitimate

Pengujian ini menjalankan ekstraktor URL Python dan model XGBoost secara lokal.
Tidak ada kunjungan browser ke 400 URL, sehingga status halaman, pengalihan,
dan label aktual pada saat uji belum diverifikasi.

## Hasil

| Model | Ambang | Kelas | Diprediksi | Benar | Salah | Tanpa prediksi | Benar / diprediksi |
|---|---:|---|---:|---:|---:|---:|---:|
| XGBoost 18 fitur, model sebelumnya | 0,38 | Phishing | 271 | 267 | 4 | 29 | 98,52% |
| XGBoost 18 fitur, model sebelumnya | 0,38 | Legitimate | 86 | 68 | 18 | 14 | 79,07% |
| XGBoost 17 fitur, dilatih ulang tanpa umur | 0,50 | Phishing | 300 | 268 | 32 | 0 | 89,33% |
| XGBoost 17 fitur, dilatih ulang tanpa umur | 0,50 | Legitimate | 100 | 50 | 50 | 0 | 50,00% |

Model 18 fitur hanya dihitung ketika tanggal registrasi domain dapat diperoleh
dari RDAP registri. Umur dihitung pada tanggal pengujian, sedangkan umur dalam
data latih berasal dari waktu pengamatan yang beragam. Model 17 fitur adalah
model baru dengan jenis algoritme yang sama, bukan model 18 fitur dengan umur
yang sekadar dikosongkan.

## Pemisahan dari data model

Di antara 300 URL berlabel phishing, 38 berada pada situs yang pernah muncul
di partisi model: 33 situs latih, 3 situs validasi, dan 2 situs uji. Tiga URL
persis terdapat dalam data model. Dalam korpus gabungan sebelum penyeimbangan,
10 URL persis sudah tercatat. Seluruh 100 URL legitimate berasal dari situs
yang tidak ditemukan pada partisi model. Karena itu, hasil phishing 300 URL
tidak boleh disebut seluruhnya sebagai uji eksternal independen.

Setelah 38 URL phishing yang tumpang tindih dikeluarkan, 262 URL tersisa.
Model 18 fitur dapat memprediksi 236 di antaranya: 233 terdeteksi phishing,
3 diprediksi legitimate, dan 26 tidak memperoleh nilai umur. Model 17 fitur
mendeteksi 241 dari 262 URL tersebut.

## Temuan yang perlu diperiksa sebelum menarik kesimpulan

- Delapan belas URL legitimate yang dinilai phishing oleh model 18 fitur dapat
  dilihat pada `prediksi_per_url.csv`. Di antaranya, `axiomxinc.com` menampilkan
  halaman penyedia hosting dan `clayburnrefractories.com` menampilkan halaman
  bawaan server. Respons HTTP 200 saja tidak cukup untuk memastikan halaman
  legitimate yang dimaksud masih aktif. Label kedua URL ini perlu ditinjau.
- Salah satu dari empat URL phishing yang diprediksi legitimate adalah alamat
  OAuth `hk.uat.mizuhoscfglobal.com`. Label URL tersebut juga perlu diverifikasi
  berdasarkan halaman dan sumber saat pengujian.
- Angka legitimate 79,07% masih di bawah target 85% pada URL yang mendapat
  prediksi. Perbedaan besar antara model 18 dan 17 fitur menunjukkan
  ketergantungan pada informasi umur domain dalam korpus ini; itu belum
  membuktikan umur domain secara kausal menentukan phishing.

`prediksi_per_url.csv` berisi satu baris per URL beserta skor kedua model,
prediksi, umur domain, status RDAP, dan tanda tumpang tindih. `ringkasan.json`
memuat hitungan dasar. `rdap_age_cache.jsonl` menyimpan hasil lookup umur.
