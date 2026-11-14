# Automation dan Rule Engine

Interu memakai aturan deterministik lokal. Tidak ada model AI, inferensi AI, atau layanan analisis eksternal.

## Cakupan aktual

- Rule Engine: 808 template total. Paket baru terdiri dari 50 artefak konfigurasi dan 6 nama backup untuk masing-masing artefak, sehingga **300 variasi path**, ditambah 100 aturan lab untuk sepuluh kategori. Itu bukan 400 jenis kerentanan yang berbeda. Aturan backup memerlukan HTTP 200 dan penanda isi file; aturan lab memerlukan status dan penanda perilaku yang sesuai, tanpa mencocokkan flag yang diharapkan. Baseline soft-404 mengurangi klaim keliru pada halaman catch-all.
- Automation menjalankan crawl, analisis respons pasif, probe parameter, dan 733 template HTTP aktif dalam satu job. Parameter bawaan: 40 halaman, kedalaman 2, 1.500 request, interval minimal 150 ms, 15 menit. Batas dapat diubah di UI.
- Probe parameter: SQLi berbasis error dan kontrol quote, refleksi XSS, LFI/XXE dengan penanda file, SSTI dengan aritmetika, RCE dengan `printf` tanpa perubahan file, SSRF ke loopback port tertutup, dan kandidat IDOR numerik. Hanya parameter yang relevan menerima probe file, XML, atau URL.
- `confirmed` menyatakan observasi yang cocok dengan bukti spesifik. SSRF, RCE, SSTI, XSS dan IDOR tetap `suspected` karena respons HTTP saja tidak membuktikan dampak atau batas otorisasi. LFI/XXE terdeteksi hanya jika penanda isi file muncul setelah probe dan tidak ada pada baseline.
- Scope dan origin dicek sebelum setiap request; redirect lintas origin dihentikan. Job berhenti saat dibatalkan, melewati batas, sesi berakhir, server memberi 429/503, atau kegagalan transport berulang. Hasil parsial tetap dapat diekspor.

## OWASP Top 10:2025

Halaman Automation menampilkan seluruh 10 kategori resmi dan membedakan sinyal otomatis dari pekerjaan manual. Kategori seperti insecure design, supply chain, integrity, dan security logging tidak dapat disertifikasi dengan probe HTTP generik. Tidak ada temuan berarti *belum ada bukti dari pemeriksaan yang dijalankan*, bukan target aman.

Rujukan: [OWASP Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/), [OWASP WSTG](https://wstg.owasp.org/), [OWASP API Security Top 10:2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/).

## Batas saat ini

- Belum ada validasi pada aplikasi target nyata atau pengukuran false positive di korpus independen.
- Crawler HTML/JS statis tidak mengeksekusi aplikasi SPA; alur bisnis dan otorisasi lintas identitas memerlukan pengujian manual.
- Sertifikat TLS target diverifikasi secara bawaan. Opsi lab di Settings dapat mengizinkan sertifikat tidak valid secara eksplisit.
- Jumlah template bukan ukuran akurasi. Operator harus memeriksa request, respons, dan konteks setiap kandidat.

## Lab lokal untuk verifikasi integrasi

Lihat [Interu 150 local lab](../lab/interu50/README.md). Lab Docker tersebut memuat 50 instance file backup terbuka dan 100 kasus dalam sepuluh kategori, masing-masing dengan flag pelatihan. Active Scan, Rule Engine, dan Pentest Automation memakai template yang sama untuk mendeteksinya. Aturan tersebut berjalan pada setiap target dalam scope, termasuk domain online dengan konten identik. Keberhasilan pada lab yang dirancang khusus ini membuktikan alur aplikasi berfungsi, tetapi **tidak** membuktikan akurasi pada target independen atau 150 jenis kerentanan.
