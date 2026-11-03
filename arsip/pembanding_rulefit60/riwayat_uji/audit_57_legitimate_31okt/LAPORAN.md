# Audit 57 keputusan legitimate yang ditandai phishing — 31 Oktober 2026

## Dasar dan batas pemeriksaan

Sumber: arsip `live_20261031_010551_638/legitimate/browser_live_analysis.json`,
ringkasan pengujian, dan `persiapan_legitimate_500_31okt/audit_500_FINAL.csv`.
Angka pengujian: 500 URL, 490 analisis selesai, 433 benar, 57 salah,
10 tanpa analisis. Ketepatan pada URL yang dianalisis ialah 88,37%; cakupan
analisis 98,0%. Sepuluh URL tanpa analisis tidak dimasukkan sebagai salah
klasifikasi model.

`audit_57_kasus.csv` memuat URL, hasil model sebelum pemeriksaan tambahan,
pemeriksaan yang aktif, kandidat brand, umur domain, dan aturan positif yang
aktif pada setiap kasus. Kolom `label_review` bukan keputusan label final.

## Pola yang ditemukan

| Kelompok | Jumlah | Temuan |
| --- | ---: | --- |
| Skor RuleFit sudah phishing | 37 | Skor mentah >= 0,80. R137 aktif pada 19 kasus. Aturan ini menggabungkan umur domain, banyak tautan internal, dan skor pencarian brand rendah. Situs organisasi atau pendidikan dengan struktur halaman ramai dapat terkena pola ini. Keaktifan aturan pada kasus salah tidak cukup untuk menyimpulkan aturan selalu keliru. |
| Pemeriksaan brand mengubah keputusan aman | 19 | Model semula memutuskan SAFE, tetapi kandidat direktori brand atau kemiripan nama pada hostname/judul memicu pemeriksaan tambahan. Nama serupa dapat merujuk organisasi lain; kandidat API bukan bukti kepemilikan domain. |
| Pemeriksaan brand pada model yang sudah phishing | 1 | Model sudah memutuskan DANGEROUS; melemahkan pemeriksaan brand tidak akan memperbaiki keputusan ini. |

Contoh penyebab pemeriksaan brand: domain kandidat `professionaltutors.com`
pada situs Professional Tutors of America sudah cocok dengan halaman, tetapi
pemeriksaan klaim brand memilih token lain dari judul. `guelphhumber.ca` juga
membawa identitas gabungan lembaga; substring nama lembaga lain bukan bukti
peniruan. Pada beberapa situs pendidikan, hasil pencarian API ialah layanan
umum seperti `eportal.id`, bukan identitas lembaga yang sedang dibuka.

Indeks 470 (`adairchs.org`) perlu verifikasi label: situs yang saat diperiksa
menampilkan konten kasino yang tidak sesuai dengan Adair County Historical
Society, sementara situs organisasi saat ini berada pada domain berbeda.
Indeks 491 juga perlu verifikasi identitas sumber ROR terhadap isi situs.
Jangan jadikan kedua kasus itu contoh aman untuk membentuk aturan sebelum
label aktual dipastikan.

## Perbaikan kandidat yang dibuat

Salinan terpisah `D:\Deployment Extension\Heurisield-GuardCandidate-31Okt`
mempertahankan model, 60 fitur, dan ambang 0,80. Keputusan *brand mismatch*
yang akan membatalkan putusan SAFE ditunda jika skor mentah model < 0,30
dan tidak teramati formulir/kolom kredensial. Pemeriksaan salah eja brand
yang terkonfirmasi dan pengalihan URL tidak diubah. Ambang 0,30 adalah
kandidat empiris dari arsip ini, bukan ambang yang telah divalidasi eksternal.

Replay arsip menunjukkan 13 dari 57 kasus terbaru akan kembali SAFE
(446/490 = 91,02% secara retrospektif); 1 kasus legitimate pada arsip
sebelumnya juga membaik. Tidak ada dari 168 URL phishing yang berhasil
dianalisis pada dua arsip pembanding berubah dari benar menjadi salah.
Hasil ini **bukan** akurasi uji independen, sebab arsip yang sama dipakai
untuk merancang dan memeriksa kandidat. Situs phishing yang tidak memuat
formulir pada saat dibuka tetap merupakan risiko yang harus diuji.

**Pembaruan setelah arsip phishing 31 Oktober:** kandidat akan mengubah
satu putusan phishing yang tadinya sesuai label feed (indeks 436,
`usps.avaturefed.net/FieldHREvent/`) menjadi aman. Identitas situs dan
label feed pada kasus ini belum diverifikasi. Karena ada potensi regresi,
kandidat **belum layak menggantikan extension utama**.

## Langkah berikutnya

1. Tinjau label indeks 470 dan 491 berdasarkan halaman dan sumber organisasi.
2. Uji salinan kandidat pada URL legitimate dan phishing baru, domain terpisah
   dari data pengembangan; bandingkan per URL dengan extension utama.
3. Untuk 37 kesalahan skor model, kumpulkan contoh legitimate sulit yang
   terverifikasi dan phishing yang sepadan. Periksa kualitas umur domain,
   brand, dan representasi halaman, kemudian latih ulang dengan validasi
   terpisah per domain. Jangan mengubah bobot aturan secara manual dari
   daftar 57 ini saja.

Extension utama `D:\Deployment Extension\Heurisield` tidak diubah oleh audit ini.
