# Diagnosis 66 URL legitimate yang diprediksi phishing

Model: XGBoost 18 fitur URL, threshold 0,38, prediksi offline tanpa membuka
halaman. Dari 300 URL berlabel legitimate, 234 diprediksi legitimate dan 66
diprediksi phishing (78,00% benar; false positive rate 22,00%).

## Pola yang terukur

| Kelompok URL | Jumlah | Salah | Salah per kelompok |
|---|---:|---:|---:|
| HTTP | 24 | 19 | 79,17% |
| HTTPS | 276 | 47 | 17,03% |

Dalam data latih, URL HTTP terdapat pada 3.471/14.934 phishing (23,24%)
dan 348/14.934 legitimate (2,33%). Model mendapat korelasi kuat antara
HTTP dan label phishing. Pada 66 kesalahan, kontribusi rata-rata fitur
`has_https_scheme` terhadap skor logit adalah +0,606; pada 234 prediksi benar
kontribusinya -0,332. Ini kontribusi lokal model, bukan ukuran sebab akibat.

Median umur domain pada kesalahan adalah 6.722 hari, dibanding 8.652 hari
pada prediksi benar. Umur yang lebih rendah menaikkan risiko relatif, tetapi
tidak menjelaskan semua kasus: banyak URL salah masih berumur ribuan hari.
Kontribusi rata-rata `domain_age_days` tetap mengurangi skor risiko, tetapi
penurunannya lebih kecil pada kelompok salah (-0,479) dibanding kelompok
benar (-1,688). Hostname yang salah cenderung lebih panjang dan memiliki
entropi lebih tinggi. Dari 66 kesalahan, 47 tetap memakai HTTPS.

## Mutu label halaman

Audit awal menemukan beberapa URL berlabel legitimate yang halaman akhirnya
perlu ditinjau: `testaverdefund.org` menampilkan `501 Not Implemented`,
`uou.ac.in` menampilkan halaman bawaan nginx, sedangkan `recondoil.com`
menampilkan `No Index` dan `unisouthasia.com` memiliki judul SEO yang tidak
jelas. Jangan otomatis mengubah labelnya tanpa pemeriksaan manual. Bahkan
jika keempat URL itu dikeluarkan, tingkat benar hanya 234/296 = 79,05%.
Jadi masalah mutu halaman tidak cukup menjelaskan penurunan keseluruhan.

## Mengapa hasil phishing sebelumnya tampak jauh lebih tinggi?

Angka 98,52% adalah 267 benar dari 271 URL phishing yang memperoleh umur
domain; 29 URL lain tidak diprediksi oleh model 18 fitur. Dari daftar phishing,
170 URL memakai `pages.dev` dan seluruh 170 itu diprediksi phishing. Data
latih mengandung 2.657 URL `pages.dev` berlabel phishing dan tidak ada
legitimate dari platform tersebut. Model tidak mempunyai fitur teks TLD
secara eksplisit, tetapi pola URL yang sering menyertai platform itu dapat
dipelajari. Selain itu, 38 URL phishing berada pada situs yang pernah
terdapat dalam partisi model. Status dan label halaman saat uji tidak
diverifikasi melalui browser. Maka angka phishing tersebut tidak setara
dengan bukti bahwa model akan mendeteksi 98% phishing baru secara umum.

## Keputusan eksperimen

Jangan mengubah threshold 0,38 atau menambah fitur hanya berdasarkan daftar
300 URL ini. Perhitungan retrospektif menunjukkan threshold 0,50 akan membuat
256/300 legitimate benar (85,33%) pada daftar yang sama, tetapi hasil itu
adalah penyetelan pada data uji dan harus diuji lagi pada daftar lain.
Prioritas: verifikasi label/halaman, perbaiki representasi legitimate HTTP
di data pengembangan, periksa kontribusi umur domain, lalu pilih threshold
dari validasi yang terpisah. Uji berikutnya harus memakai URL baru dari kedua
kelas pada periode yang sama.
