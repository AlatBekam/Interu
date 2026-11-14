# Uji independen Interu 1.2.0 — 14 November 2026

## Ringkasan

Interu berhasil menjalankan pemindaian terbatas pada **dua aplikasi demo online milik pihak lain** dan satu OWASP Juice Shop Docker yang tidak dibuat untuk aturan Interu. Hasil ini lebih representatif daripada lab RUY 150 kasus, tetapi belum menjadi pengukuran sensitivitas/false positive formal karena belum ada inventaris ground truth per endpoint dan per versi target.

**Nilai setelah uji ini: software keseluruhan 6/10; kemampuan deteksi kerentanan web otomatis pada target independen 4,5/10.** Interu bekerja sebagai workstation dan menemukan satu refleksi HTML berbahaya di Altoro Mutual. Sebagian besar hasil lainnya adalah header/cookie atau informasi. Crawler menghabiskan anggaran halaman untuk URL palsu yang diekstrak dari JavaScript, dan 733 aturan aktif tidak menambah satu temuan pada Gin and Juice Shop.

## Target, batas, dan hasil

| Target | Metode | Request | Hasil scanner |
|---|---|---:|---|
| PortSwigger Gin and Juice Shop, `https://ginandjuice.shop/` | Crawl + probe parameter; GET saja, 2 rps, maks. 180 request, satu origin | 65 | 11 temuan: 8 observasi header/cookie, 3 kandidat IDOR yang tidak terbukti |
| Target yang sama | Seluruh 733 aturan HTTP aktif; GET saja, sekitar 2,9 rps, satu origin | 735 | 8 observasi header/cookie yang sama; **0 temuan tambahan dari aturan aktif** |
| HCL/IBM Altoro Mutual, `http://demo.testfire.net/` | Crawl + probe parameter; GET saja, 2 rps, maks. 160 request, satu origin | 50 | 12 temuan: 1 refleksi HTML yang berpotensi XSS, 2 form tanpa token CSRF, 1 fingerprint Tomcat tidak terversi, 8 observasi header/cookie/teknologi |
| OWASP Juice Shop resmi di Docker, `http://127.0.0.1:3001/` | Crawl + probe parameter + seluruh aturan aktif; GET saja, satu origin | 792 | 5 temuan: CORS wildcard, CSP/Referrer-Policy tidak ada, `security.txt`, dan `robots.txt`; **0 temuan SQLi/XSS/IDOR/SSRF/XXE** pada run ini |

Kedua demo online memang disediakan untuk pemindaian: [panduan scan PortSwigger](https://portswigger.net/burp/documentation/desktop/getting-started/running-your-first-scan) dan [tutorial AppScan untuk Altoro Mutual](https://www.ibm.com/docs/en/sas/9.0.3?topic=SSPH29_9.0.3%2Fcom.ibm.help.common.infocenter.aps%2Fc_Tutorial030.htm). OWASP [menyediakan Juice Shop sebagai aplikasi rentan untuk menguji tool](https://github.com/juice-shop/juice-shop). `testphp.vulnweb.com` sudah dicoba tetapi koneksi dari komputer ini timeout; target itu **tidak dihitung** dalam hasil.

## Pemeriksaan temuan

1. **Altoro: refleksi HTML yang dapat dieksekusi — bukti kuat.** Interu menandai `search.jsp?query=1` karena tag uji muncul utuh dalam respons HTML. Request ulang dengan `<x-interu-verify>` menunjukkan tag tersebut langsung menjadi bagian halaman. Request terpisah dengan marker `svg onload` menghasilkan HTTP 200; saat **respons yang sama diputar di browser lokal** dengan semua request keluar diblokir, marker JavaScript berjalan. Navigasi langsung browser ke URL payload diblokir oleh browser pada mesin ini, sehingga pengujian tersebut belum membuktikan eksekusi melalui navigasi live pada browser tanpa perlindungan. Ini adalah satu hasil substansial; scanner sendiri secara tepat melabelinya *suspected*, bukan *confirmed*. Bukti: [laporan Altoro](audit/altoro-online-benchmark.json) dan [verifikasi browser](audit/altoro-xss-verification.json).
2. **Gin and Juice Shop: tiga kandidat IDOR tidak boleh dihitung sebagai kerentanan.** `searchTerm=1`, `productId=3`, dan `postId=4` menghasilkan respons berbeda ketika angka diganti, tetapi produk dan blog dapat diakses tanpa login. Empat request pemeriksaan untuk produk 2/3 dan post 3/4 semuanya HTTP 200 tanpa sesi. Perubahan ID pada objek publik tidak membuktikan bypass otorisasi. Parameter `searchTerm` bahkan dipilih karena nilainya angka, walau namanya bukan identitas objek. Bukti: [laporan crawl/probe](audit/online-benchmark.json) dan [kontrol akses tanpa login](audit/ginandjuice-idor-control.json).
3. **Header/cookie:** ketiadaan CSP/HSTS/Referrer-Policy dan atribut cookie adalah observasi konfigurasi yang dapat diperiksa dari respons. Itu tidak setara dengan eksploitasi aplikasi. Pada Gin and Juice Shop, beberapa alert cookie berkaitan dengan `AWSALB` milik load balancer, bukan bukti cookie autentikasi yang bocor. Pada Juice Shop, `security.txt` tersedia adalah informasi, bukan kerentanan. CORS `*` belum dibuktikan mengekspos data sensitif lintas origin. Bukti: [aturan aktif Gin and Juice Shop](audit/online-active-rules.json), [Juice Shop lokal](audit/juice-independent-benchmark.json).
4. **Altoro: CSRF dan Tomcat masih kandidat.** Form login/feedback terlihat tanpa token anti-CSRF, tetapi tidak ada pengujian aksi lintas situs atau pembuktian dampak. Banner `Apache-Coyote/1.1` tidak membuktikan versi Tomcat atau salah satu dari enam CVE yang disebut oleh fingerprint.

## Kelemahan yang terlihat langsung

- **Crawler menafsirkan potongan JavaScript sebagai URL.** Log Gin and Juice Shop berisi path seperti `/resources/js/==`; log Juice Shop berisi path seperti `/null;get` dan `/%60%60;_removeListenerFns=...`. Pada Juice Shop ini menghabiskan 40 jatah halaman, sehingga endpoint aplikasi yang benar banyak tidak dijelajahi.
- **Cakupan aplikasi modern lemah.** Crawler membaca HTML/JS statis, tanpa menjalankan SPA. Pemindaian tanpa login dan probe parameter GET tidak menjangkau banyak alur Juice Shop yang memakai JavaScript, API, atau aksi POST.
- **Jumlah aturan bukan ukuran akurasi.** Dari 808 template, 300 adalah variasi path untuk 50 keluarga backup dan 100 khusus kasus lab RUY. Uji seluruh 733 aturan aktif pada Gin and Juice Shop menghasilkan nol temuan baru di luar observasi pasif.
- **Pelabelan perlu lebih ketat.** Kandidat IDOR pada objek publik dan alert cookie load balancer mudah memberi kesan kerentanan yang lebih kuat daripada bukti sebenarnya. `confirmed` pada header berarti kondisi header teramati, bukan dampak keamanan sudah terbukti.

## Kesimpulan dan prioritas perbaikan

Interu sudah layak sebagai **workstation pemindaian dan pengumpul bukti awal**. Ia belum layak mengklaim deteksi otomatis kuat pada beragam aplikasi nyata berdasarkan uji ini. Hasil terbaik di luar lab RUY adalah kandidat XSS Altoro yang didukung respons server dan verifikasi browser lokal. Tidak ada bukti dari run ini bahwa Interu berhasil menemukan kerentanan inti OWASP Juice Shop.

Urutan perbaikan paling berdampak: (1) perbaiki ekstraksi URL dari JavaScript dan tolak path sampah; (2) tambahkan crawling browser/API untuk SPA; (3) uji parameter POST dan sesi terautentikasi secara aman; (4) hentikan label IDOR bila tidak ada pembuktian batas kepemilikan; (5) pisahkan temuan informasi/header dari kerentanan eksploitabel; (6) ukur precision/recall pada benchmark dengan ground truth yang terpisah dari aturan scanner. Setelah perbaikan, jalankan ulang target yang sama dengan batas request yang sama agar perbandingannya adil.

## Berkas bukti

- [Konektivitas Gin and Juice Shop](audit/online-connectivity.json)
- [Crawl dan probe Gin and Juice Shop](audit/online-benchmark.json)
- [Kontrol objek publik Gin and Juice Shop](audit/ginandjuice-idor-control.json)
- [Seluruh aturan aktif pada Gin and Juice Shop](audit/online-active-rules.json)
- [Crawl dan probe Altoro Mutual](audit/altoro-online-benchmark.json)
- [Verifikasi refleksi dan eksekusi marker Altoro](audit/altoro-xss-verification.json)
- [OWASP Juice Shop Docker](audit/juice-independent-benchmark.json)
- [Uji integrasi lab RUY 150 kasus (pembanding internal)](audit/lab-ui-verification.json)

Data JSON mencatat status, jumlah request, error, nama temuan, evidence ringkas, dan log. Token cookie dan respons lengkap tidak disalin ke laporan ini.
