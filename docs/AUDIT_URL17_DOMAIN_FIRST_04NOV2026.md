# URL17 0.3.2 — domain-first brand dan diagnosis legitimate

## Hasil pengujian pengguna

Pada pengujian 400 legitimate terbaru, URL17 0.3.1 menyelesaikan 397 analisis: 320 SAFE, 77 DANGEROUS, specificity 80,60%; coverage 99,25%. Tiga URL tanpa analisis terdiri atas dua HTTP 403 dan satu halaman dimuat tanpa analisis model. Pembanding URL18 menyelesaikan 395 analisis: 314 benar, 81 salah, specificity 79,49%. Jumlah sampel selesai berbeda, sehingga angka tersebut bukan perbandingan berpasangan yang sempurna.

Semua 77 salah blokir URL17 berasal dari keputusan URL model. Kelompok pemerintah 19/60 salah, pendidikan 15/98, perusahaan 22/120, dan kesehatan/nonprofit 21/119. Kandidat domain cocok telah tercatat pada 40 kasus, tetapi official_domain_match masih unknown pada 75 dari 77 kasus. Status brand: 35 identified, 21 ambiguous, 21 unknown. Hanya 26 dari 77 kasus memiliki skor di bawah 0,60; identifikasi domain saja belum tentu mengatasi 51 skor lebih tinggi.

Hostname pada kelompok salah blokir rata-rata lebih panjang (19,104 vs 16,069 karakter), berentropi lebih tinggi (3,457 vs 3,221), dan lebih banyak tanda hubung (0,338 vs 0,072). Ini asosiasi dari rekaman, bukan bukti kausal kontribusi masing-masing fitur. Model URL perlu pengembangan lebih lanjut bila target specificity belum tercapai; domain ditemukan di direktori tidak otomatis membatalkan semua keputusan phishing.

## Perubahan brand

1. Pisahkan registrable domain menggunakan parser suffix yang sudah tersedia.
2. Cari domain di Clearbit, kemudian Brandfetch, kemudian API domain HeuriShield jika belum menemukan kecocokan persis.
3. Simpan nama brand, domain kandidat, sumber provider, status HTTP/lookup dan hasil domain-first untuk replay.
4. Gunakan token jika hasil domain kosong/gagal, ada label hostname tambahan, atau identitas halaman perlu diperiksa terhadap pemilik domain. Domain pemilik yang ditemukan tidak menutupi klaim brand lain pada halaman.
5. Bedakan kecocokan kandidat dari verifikasi provider dan keputusan akhir. Kegagalan API bukan no_match; hasil parsial menggunakan TTL singkat. Registri penyedia OAuth lama tetap berlaku.

Perubahan sebelumnya pada 0.3.1 (diagnostik/cooldown API, indikasi domain referensi tersisip, judul brand pada password form, dan DOM dinamis) disertakan dalam folder URL17. URL18 dipertahankan sebagai pembanding.

## Pengujian dan keterbatasan

17 kelompok pemeriksaan lulus, termasuk domain-first exact-match/fallback, konflik BCA pada subdomain, OAuth, allow/block list, replay, SPA fixture, dan pemuatan extension di Chromium. Kesetaraan model Python–JavaScript pernah diperiksa pada 800 URL: nol perbedaan keputusan.

Replay URL17 0.3.1 ke kandidat 0.3.2 memakai fitur URL dan bukti tersimpan yang sama: phishing 114/132 tetap 114/132; legitimate terbaru 320/397 tetap 320/397; dua arsip legitimate lain 369/487 dan 304/491 tetap sama. Tidak ada regresi tambahan pada rekaman tersebut. Arsip lama tidak memiliki respons pencarian domain-first; replay menandai bukti itu belum direkam dan memakai fallback token tersimpan. Karena itu, peningkatan jumlah brand yang ditemukan dan penurunan waktu API pada domain-first memerlukan pengujian baru. Hasil 80,60% belum dinyatakan meningkat.

Label feed dan laporan asli tetap dipertahankan. Tidak ada pengujian live pengguna yang dijalankan ulang oleh agen pada perubahan ini.
