# Perbandingan enam model untuk 18 fitur URL

## Rancangan uji

- Sumber: `DATA_URL_18_FITUR.csv`, 29.868 baris; masing-masing 14.934 legitimate dan phishing.
- Fitur: 17 fitur teks URL dan `domain_age_days`. Tidak ada fitur DOM atau brand.
- Pemisahan menurut situs terdaftar dengan Public Suffix List yang mencakup layanan hosting privat. Satu situs tidak muncul di lebih dari satu partisi.
- Latih: 23.779 baris; validasi: 3.105; uji: 2.984. Threshold tiap model dipilih dari validasi untuk memaksimalkan hasil kelas yang lebih lemah. Data uji tidak dipakai memilih threshold.
- Enam algoritme: Logistic Regression, Random Forest, Extra Trees, Histogram Gradient Boosting, XGBoost, dan RuleFit (tanpa komponen linear, batas 150 aturan).

## Hasil pada data uji internal

| Model | Threshold validasi | Balanced accuracy | Legitimate benar | Phishing terdeteksi | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Extra Trees | 0,42 | 92,08% | 91,52% | 92,64% | 124 | 112 |
| XGBoost | 0,38 | 91,97% | 90,84% | **93,10%** | 134 | **105** |
| Random Forest | 0,40 | 91,60% | 90,64% | 92,57% | 137 | 113 |
| Histogram Gradient Boosting | 0,35 | 91,53% | 90,23% | 92,83% | 143 | 109 |
| RuleFit | 0,15 | 90,87% | 90,29% | 91,45% | 142 | 130 |
| Logistic Regression | 0,48 | 89,22% | 86,26% | 92,18% | 201 | 119 |

FP adalah URL legitimate yang diprediksi phishing; FN adalah URL phishing yang diprediksi legitimate. Total data uji: 1.463 legitimate dan 1.521 phishing. Extra Trees memberi balanced accuracy tertinggi pada data uji, tetapi **Histogram Gradient Boosting dipilih oleh data validasi**. Selisih antarmodel teratas kecil dan hasil uji tidak dipakai untuk mengganti pilihan validasi. RuleFit menghasilkan 146 aturan aktif; threshold 0,15 adalah hasil validasi model baru ini dan tidak dapat dibandingkan langsung dengan threshold 0,80 model lama.

## Pemeriksaan pengaruh umur domain

Dengan partisi dan prosedur threshold yang sama, tiga kandidat kuat dilatih ulang menggunakan 17 fitur URL **tanpa** umur domain:

| Model | Balanced accuracy tanpa umur | Legitimate benar | Phishing terdeteksi |
|---|---:|---:|---:|
| Extra Trees | 86,86% | 86,88% | 86,85% |
| XGBoost | 86,61% | 87,42% | 85,80% |
| Histogram Gradient Boosting | 86,57% | 87,22% | 85,93% |

Umur memberi peningkatan sekitar lima poin pada korpus ini. Akan tetapi, umur berasal dari waktu pengamatan berbeda; pada layanan hosting publik angka tersebut dapat menunjukkan umur platform. Median umur pada sumber: legitimate 8.805 hari dan phishing 2.246 hari. Peningkatan offline ini belum membuktikan kontribusi yang sama pada URL live baru.

## Batas kesimpulan

Ini adalah **holdout internal**, bukan uji live independen. Dataset telah diseimbangkan sebelum pembagian sehingga prevalensi uji tidak mencerminkan prevalensi nyata. Beberapa label berasal dari feed atau pengujian lama dan tidak diverifikasi ulang pada saat pelatihan. Perlu uji baru dengan situs legitimate dan phishing yang statusnya diverifikasi, terutama pada layanan hosting publik serta pada URL dengan umur domain yang tidak tersedia.

Rincian angka ada di `perbandingan_model.csv`, metrik validasi dan uji di `evaluasi_model.json`, partisi di `pembagian_data.csv`, prediksi per URL di `prediksi_data_uji.csv`, serta model terlatih di folder `model/`. Hasil ablasi ada di `uji_tanpa_umur.json`.
