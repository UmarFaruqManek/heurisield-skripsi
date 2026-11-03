# Tinjauan seluruh referensi lokal untuk rancangan URL Analyzer

Sumber: 43 PDF di `D:\Deployment Extension\Refrensi SkripsiKU`. Semua berkas dibuka sebagai PDF dan teks tiap halamannya diindeks melalui `audit_referensi.py`: 665 dari 674 halaman menghasilkan teks yang dapat dibaca. Sembilan halaman berupa gambar/teks sangat sedikit terdapat hanya pada laporan BSSN (hlm. 16, 42, 62, 66, 122) dan laporan KOMINFO-CSIRT (hlm. 1, 4, 5, 9); keduanya dipakai sebagai konteks, bukan dasar fitur URL. Penilaian berikut memakai isi judul/abstrak, bagian metode, dan bagian fitur yang relevan. **Relevan** berarti dapat membantu memilih/mengevaluasi fitur URL; tidak berarti semua fitur atau klaim artikel diterima tanpa pengujian.

| No. | Berkas PDF (nama disingkat bila sangat panjang) | Peran untuk eksperimen |
|---:|---|---|
| 1 | A Large-Scale Analysis of Phishing Websites Hosted on Free Web Hosting Domains | **Penting:** phishing pada hosting gratis, pembagian URL/HTML; umur domain platform dapat menyesatkan (PDF hlm. 5–6). |
| 2 | A Study on Malicious Browser Extensions | Keamanan extension; tidak menjadi dasar fitur phishing URL. |
| 3 | A systematic literature review on phishing website detection techniques | Survei pendekatan dan keterbatasan; dasar konteks, bukan definisi satu fitur tertentu. |
| 4 | Alat OSINT Berbasis Web untuk Deteksi URL Phishing Menggunakan Integrasi API | Pendekatan API/OSINT; berguna untuk metadata, bukan fitur leksikal utama. |
| 5 | An Efficient Phishing Website Detection Plugin Service Based on Website Trustworthiness Evaluation | Membahas struktur URL, domain dan redirect bersama konten; perlu memisahkan jenis data saat menerapkan. |
| 6 | AN INTELLIGENT BROWSER EXTENSION FOR PHISHING WEBSITE DETECTION USING MACHINE LEARNING MODELS | Arsitektur extension dan pembandingan model; tidak merinci kontrak fitur URL yang kuat. |
| 7 | Analisis Serangan Phising dan Upaya Pencegahannya pada Website | Konteks ancaman/penanggulangan; bukan dasar fitur numerik URL. |
| 8 | Are Adversarial Phishing Webpages a Threat in Reality? | Perilaku dan persepsi pengguna terhadap halaman adversarial; relevan bagi evaluasi peringatan, bukan ekstraksi URL. |
| 9 | Browser Extension for Fake URL Detection | Arsitektur deteksi dan unsur HTML; berkas lama/kurang spesifik untuk kontrak fitur baru. |
| 10 | Browser Extension for Phishing Website Detection Using Machine Learning | **Relevan:** PDF hlm. 2 menyebut panjang URL, karakter `@`/`//`, HTTPS, subdomain, dan umur domain; juga JavaScript/form sebagai bagian terpisah. |
| 11 | dddd | Isi adalah artikel metode *prototype* pengembangan sistem; nama file tidak informatif, bukan dasar fitur URL. |
| 12 | Deep Dive into Client-Side Anti-Phishing: A Longitudinal Study | Evaluasi sistem anti-phishing sisi klien; membantu desain uji live dan keterbatasan. |
| 13 | Detecting Phishing Sites - An Overview | Tinjauan deteksi phishing dan klasifikasi; sumber konteks, bukan spesifikasi ekstraksi. |
| 14 | Deteksi Url Phishing Menggunakan Algoritma Support Vector Machine Berbasis Website | Terbitan terlihat 2020 pada halaman pertama; tidak diprioritaskan ketika tersedia sumber 2022–2026. |
| 15 | Deteksi URL Phishing Menggunakan NLP dan SVM Berbasis Machine Learning | **Relevan:** panjang URL, titik, garis miring, pola teks (PDF hlm. 1, 5); TF-IDF adalah metode lain yang belum dipilih. |
| 16 | Deteksi Website Phishing Dari Analisis Url Menggunakan Algoritma Random Forest | **Relevan:** tabel fitur URL/domain dan umur registrasi (PDF hlm. 3, 5). Tabel yang sama juga mencampur DOM dan jaringan; ambang kategorikal penulis tidak otomatis dipakai. |
| 17 | DETEKSI WEBSITE PHISHING MENGGUNAKAN TEKNIK FILTER PADA MODEL MACHINE LEARNING | Relevan untuk seleksi fitur dan pembedaan URL, halaman, domain; *entropy* yang disebut di PDF adalah entropi pohon keputusan, **bukan** entropi string URL. |
| 18 | Developers Insight On Manifest v3 Privacy and Security Webextensions | Implementasi/privasi extension; tidak menjadi rujukan karakteristik URL. |
| 19 | Fake Website Detection Browser Extension: Rule-Based and API-Assisted Security Tool | Desain kombinasi indikator dan API; bobot manualnya tidak ditransfer ke model. |
| 20 | From Past to Present: A Survey of Malicious URL Detection Techniques | **Penting:** PDF hlm. 6 membedakan fitur leksikal dari metadata jaringan, serta mengulas path, parameter dan subdomain. |
| 21 | GuardSurfing: Ekstensi Browser ... XGBoost | Desain pengujian extension/model; daftar fitur perlu dibaca dengan pemisahan URL dan halaman. |
| 22 | Heuristic-Based Phishing Site Detection | Tesis yang menguraikan URL, umur domain, dan fitur halaman; berguna sebagai konteks, tetapi bukan jurnal utama untuk daftar akhir. |
| 23 | Implementasi Ekstensi Google Chrome ... Random Forest | Konteks implementasi extension dan model lokal; ekstraksi fitur halaman perlu dipisahkan dari URL. |
| 24 | Implementasi Metode Random Forest Klasifikasi untuk Phishing Link Detection | Konteks pemodelan/dataset; bukan sumber terkuat untuk definisi URL mentah. |
| 25 | Implementasi Website Deteksi Phishing Link Menggunakan SSL Validation dan URL Scoring | Konteks SSL dan skor URL; sertifikat TLS tidak sama dengan boolean skema HTTPS dan memerlukan pemeriksaan jaringan. |
| 26 | Klasifikasi Malicious URL Menggunakan Improved Random Forest ... | **Relevan:** PDF hlm. 2 menjelaskan fitur leksikal seperti panjang URL, titik, karakter khusus, panjang domain, protokol dan TLD; mengingatkan bahwa fitur leksikal saja terbatas. |
| 27 | Know URL: Machine Learning-based Chrome Extension ... | Implementasi URL dan beberapa fitur host/anchor; anchor termasuk DOM, bukan URL mentah. |
| 28 | Lanskap Keamanan Siber Indonesia 2024 (BSSN) | Laporan konteks ancaman; bukan sumber definisi fitur. |
| 29 | LAPORAN AKTIVITAS ABUSE DOMAIN .ID | Laporan konteks penyalahgunaan domain .id; tidak membenarkan memberi label phishing pada TLD tertentu. |
| 30 | LAPORAN 2024 TAHUNAN KOMINFO-CSIRT | Laporan konteks insiden; bukan dasar numerik model URL. |
| 31 | Penerapan Algoritma Klasifikasi pada Machine Learning untuk Deteksi Phishing | **Relevan:** PDF hlm. 5 menyebut panjang URL, tanda hubung, titik, HTTPS, jenis domain dan panjang subdomain. Datasetnya mencakup kelas selain phishing/benign. |
| 32 | `Perancangan Perangkat Lunak untuk Menggambar Diagram Berbasis Android.pdf` | **Nama file salah:** isi sebenarnya *Klasifikasi URL Berbahaya Menggunakan Algoritma Random Forest Berbasis Fitur Struktural* (2025). PDF hlm. 2–3 mencantumkan fitur, tetapi juga menyebut anchor, DNS dan umur domain sebagai “struktural”; itu bukan semua fitur URL mentah. |
| 33 | `Perancangan Perangkat Lunak untuk Menggambar Diagram Berbasis.pdf` | Benar-benar artikel perancangan diagram Android; tidak relevan untuk fitur phishing URL. |
| 34 | Phish Guard: A Client-Side Heuristic-Based Phishing URL Detection System | URL/IP/`@`/kata kunci (PDF hlm. 2–3). Daftar brand/TLD dan bobot manual bukan kontrak model ini. |
| 35 | PHISHING ACTIVITY TRENDS REPORT (APWG) | Statistik ancaman, bukan sumber definisi fitur. |
| 36 | `phising url detection.pdf` | **Penting:** isinya Kim dkk. (2022), *Phishing URL Detection: A Network-based Approach Robust to Evasion*. PDF hlm. 14 Lampiran A mencantumkan 19 fitur baseline leksikal/host/domain. Hasil peringkatnya berasal dari baseline Random Forest mereka, bukan jaminan untuk data kita. |
| 37 | RANCANG BANGUN SISTEM PENDETEKSI LINK PHISHING ... RANDOM FOREST | Konteks sistem berbasis URL dan model; tidak lebih rinci daripada sumber fitur utama. |
| 38 | Real-time and Lightweight Phishing Prevention based on SSL Certificates and User Authentication Forms | **Penting untuk tahap DOM:** bukti sertifikat dan form autentikasi, bukan fitur URL mentah. |
| 39 | Real time identification of phishing attacks through machine learning enhanced browser extensions | **Relevan untuk pemisahan tahap:** PDF hlm. 8 membedakan address bar, domain, HTML/JavaScript, dan fitur abnormal; membahas seleksi fitur. |
| 40 | Real-Time URL-Based Phishing Detection Using XGBoost and Browser Extension Integration | **Relevan:** PDF hlm. 5 menguraikan leksikal, rasio karakter, entropi, domain, kata kunci, dan brand. Fitur brand dipisahkan dari model URL di rancangan kita. |
| 41 | Rule-Based Approach for Detecting Phishing Websites through Browser Extension | Contoh aturan URL, umur, form eksternal, dan API (PDF hlm. 2). Ambang/aturan penulis tidak dipakai langsung. |
| 42 | UML Diagrams in Software Engineering Research | Rujukan diagram/metodologi perangkat lunak, bukan fitur URL. |
| 43 | “Explain, Don’t Just Warn!” — A Real-Time Framework for Generating Phishing Warnings with Contextual Cues | Rujukan desain penjelasan peringatan; bukan daftar fitur model URL. |

## Implikasi untuk pilihan fitur

1. **Tetap mulai dari 17 kolom kandidat** di `README.md`, lalu uji setiap fitur. Survei 43 PDF tidak berarti seluruh fitur dari seluruh penelitian harus digabungkan.
2. **Umur domain bukan fitur leksikal URL.** Nilainya memerlukan tanggal registrasi, tanggal acuan, dan status ketersediaan. Untuk subdomain layanan hosting publik, umur registrasi platform tidak menggambarkan umur halaman (no. 1, PDF hlm. 5).
3. **Fitur yang menyentuh HTML, sertifikat, respons HTTP, redirect aktual, atau API brand** diletakkan pada tahap/metadata terpisah. Menyebutnya “fitur URL” hanya karena muncul pada tabel penelitian akan merusak kesetaraan ekstraksi dataset dan extension.
4. **Jangan mengadopsi ambang tetap dari referensi** (misalnya panjang URL tertentu atau usia enam bulan) sebagai putusan otomatis. Nilai pada situs legitimate, shared hosting, dan halaman login dapat tumpang tindih dengan phishing.
5. **Kebutuhan berikutnya adalah audit ketersediaan data riwayat:** URL awal, label aktual yang dapat dipertanggungjawabkan, tanggal registrasi, tanggal acuan, dan asal halaman. Baru setelah itu fitur serta model kandidat bisa dievaluasi.
