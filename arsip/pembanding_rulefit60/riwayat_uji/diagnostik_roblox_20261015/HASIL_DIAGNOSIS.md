# Diagnosis Live Roblox

URL: https://www.roblox.com/

Pengujian satu URL memakai Chromium dan extension unpacked versi 5.0.2 dalam profil baru,
bukan prediksi offline saja. Fitur dan analisis asli disimpan di analysis.json serta
extension_storage.json; browser.png menunjukkan halaman yang terbuka.

## Hasil yang teramati

- Keputusan extension: SAFE.
- Probabilitas phishing RuleFit: 0.05639108224407466 (5.64%).
- Threshold: 0.80.
- Kandidat: Roblox, roblox.com, sumber Clearbit.
- Skor pencarian: 120.714584; qualityScore: 0.9615349423068125; sumber skor Brandfetch.
- Domain awal dan final cocok dengan domain kandidat.
- RDAP tersedia; umur domain: 8293 hari.
- Resource: 162; script: 127; script eksternal: 111.
- Anchor: 22; internal: 14; eksternal: 8; rasio eksternal: 0.363636.
- Form kredensial ke domain luar/IP: 0/0.
- Field fitur tersedia: 60/60; model memiliki 150 rule dan 33 rule terpenuhi.
- SELF_BRAND_DOMAIN_GUARD tercatat, tetapi model sendiri sudah SAFE.
  Tidak ada original_verdict DANGEROUS pada hasil ini; guard tidak diperlukan untuk mengubah label.

## Rule pendukung risiko dan pengurang risiko

Sebagian rule risiko aktif: R150 (+2.43095), R055 (+2.09834), R149 (+1.62406),
dan R010 (+1.52998), berkaitan dengan struktur resource/script/link halaman.
Rule legitimate juga aktif, misalnya R019 (-1.78966) untuk kecocokan domain brand
dan kualitas kandidat, serta R048 (-1.32288) yang melibatkan umur domain dan struktur URL/link.
Penjumlahan seluruh kontribusi termasuk intercept menghasilkan logit -2.81740,
sehingga probabilitas akhirnya tetap 5.64%, bukan phishing.

## Replay diagnostik, bukan observasi live tambahan

Pada vector fitur live yang sama, skor pencarian dan kualitas dibuat null secara offline:
model tetap SAFE 5.64% karena median train melewati percabangan yang sama.
Ketika kandidat brand juga dibuat tidak ditemukan, model menjadi SAFE 26.35%.
Hasil simulasi ini disimpan di model_replay.json.

Dengan demikian, pemblokiran yang dilaporkan pengguna belum berhasil direproduksi
pada kunjungan ini. Skor API kosong saja tidak terbukti sebagai penyebab untuk vector
yang teramati. Bug guard yang sebelumnya hanya menerima Brandfetch memang ada dan
sudah diperbaiki, tetapi tidak membuktikan penyebab spesifik pemblokiran sebelumnya.
Untuk membuktikannya diperlukan analisis yang tersimpan tepat saat URL diblokir;
versi extension, cache, waktu pembacaan DOM, respons API dan fitur saat itu dapat berbeda.
Tidak ada whitelist khusus Roblox yang digunakan dalam diagnosis ini.
