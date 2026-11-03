# Audit pengaruh fitur dan mutu data XGBoost URL

## Definisi angka

Data hitung adalah partisi uji internal yang sudah dibekukan: 2.984 URL
(1.463 legitimate, 1.521 phishing). Model adalah `XGBoost.joblib` dengan
18 fitur. `gain_global_persen` membagi total gain seluruh pemisahan pohon
menjadi 100%. Dua kolom kontribusi kelas menghitung porsi kontribusi logit
XGBoost yang mendukung label aktual pada masing-masing kelas, lalu
dinormalisasi menjadi 100% per kelas. Persentase ini bukan peluang label,
bukan dampak sebab-akibat, dan tidak berarti model menggunakan satu fitur
secara terpisah.

| Fitur | Gain global | Mendukung legitimate | Mendukung phishing |
|---|---:|---:|---:|
| has_https_scheme | 27,36% | 9,01% | 11,00% |
| domain_age_days | 14,25% | 37,17% | 37,18% |
| path_length | 8,01% | 4,46% | 5,24% |
| hyphen_count | 6,53% | 2,68% | 7,68% |
| path_hyphen_count | 6,20% | 9,03% | 3,79% |
| hostname_entropy | 5,20% | 3,89% | 3,97% |
| has_at_symbol | 4,41% | 0,71% | 0,33% |
| hostname_length | 4,02% | 5,81% | 6,58% |
| path_depth | 3,73% | 1,13% | 1,00% |
| url_entropy | 3,56% | 5,61% | 3,34% |
| digit_ratio | 3,28% | 2,45% | 4,94% |
| dot_count | 3,04% | 0,85% | 2,60% |
| subdomain_count | 2,82% | 6,92% | 4,46% |
| query_length | 2,54% | 1,78% | 1,99% |
| special_char_count | 2,01% | 4,17% | 2,62% |
| url_length | 1,70% | 3,73% | 2,79% |
| sensitive_token_count | 1,35% | 0,60% | 0,50% |
| has_ip_host | 0,00% | 0,00% | 0,00% |

Rincian angka dan median nilai fitur tersedia di `pengaruh_fitur_18.csv`.

## Temuan data

1. Dataset model berisi 29.868 URL seimbang (14.934 per kelas), tanpa nilai
   fitur kosong atau URL duplikat. Sumber gabungan yang memiliki umur berisi
   36.828 URL; jauh lebih kecil daripada inventaris awal 614.818 URL yang
   sebagian besar tidak memiliki umur. Artinya, syarat umur tersedia adalah
   mekanisme seleksi data yang kuat. Model terlatih pada subset tersebut.
2. URL HTTP terdapat pada 3.471 phishing (23,24%) tetapi hanya 348 legitimate
   (2,33%). Ketimpangan ini menjelaskan mengapa HTTP menjadi pemisah yang
   kuat dan mengapa 19 dari 24 legitimate HTTP baru salah diprediksi.
3. Median umur domain adalah 8.805 hari untuk legitimate dan 2.246 hari
   untuk phishing. Umur disalin dari sumber dengan waktu pengamatan berbeda.
   Pada subdomain hosting, umur yang tersedia dapat menjadi umur platform,
   bukan umur halaman/tenant.
4. Ada 2.657 URL `pages.dev` berlabel phishing dan tidak ada legitimate dari
   platform itu. Ini menimbulkan risiko model mempelajari pola penyedia
   hosting/sumber data. Model tidak memakai teks TLD sebagai fitur langsung,
   tetapi pola panjang, tanda hubung, dan umur platform dapat menyertainya.
5. `has_ip_host` selalu 0 pada kedua kelas, sehingga model belum belajar
   menilai URL berhost IP. `has_at_symbol` juga jarang: 52 legitimate dan 193
   phishing; gain besar pada fitur langka tidak berarti fitur itu dominan
   pada sebagian besar URL.
6. Inventaris awal mencampur sumber internal, dataset eksternal, dan riwayat
   uji live. Dalam dataset model, sedikitnya 54 URL memiliki status riwayat
   yang memuat `no_valid_analysis`, `http_error`, atau `error_or_challenge_page`.
   Status tersebut tidak otomatis membuktikan label salah, tetapi perlu
   ditinjau sebelum dipakai sebagai contoh pelatihan berikutnya.
7. Data seimbang dibuat sebelum pembagian latih/validasi/uji. Pemisahan situs
   antarpartisi mencegah situs tenant yang sama muncul di dua partisi, tetapi
   distribusi pada penyedia hosting tetap dapat serupa. Prevalensi uji
   internal juga tidak mewakili prevalensi nyata.

## Kesimpulan

Tidak ditemukan kesalahan sederhana berupa fitur kosong atau URL duplikat pada
file model. Masalah utama adalah **representativitas dan provenance**:
ketimpangan HTTP, dominasi contoh hosting tertentu, seleksi hanya URL dengan
umur tersedia, umur dari tanggal pengamatan berbeda, dan status halaman
historis yang belum disaring penuh. Sebelum menambah fitur atau mengubah
threshold, benahi mutu contoh legitimate/phishing yang terverifikasi lalu
nilai ulang pada uji baru yang dipisahkan per situs dan sumber.
