# Evaluasi Interu 1.3.0 pada 10 target independen — 14 November 2026

## Kesimpulan

Perbaikan crawler, pemeriksaan SQLi SQLite, dan pengetatan bukti IDOR meningkatkan hasil nyata dibanding baseline 1.2.0. Interu menemukan **3 sinyal SQL injection MySQL dan 1 disclosure file lokal** pada DVWA online, serta **1 SQL injection SQLite** pada OWASP Juice Shop Docker. Uji VAmPI lokal sesudah run 10 target juga menemukan respons JSON yang memuat field `password` pada 3 akun; nilai field tidak disalin ke laporan. Temuan XSS Altoro tetap kandidat, walaupun verifikasi browser lokal sebelumnya menunjukkan marker dapat dieksekusi pada respons yang diputar ulang.

**Penilaian sementara: keseluruhan 6,5/10; deteksi otomatis pada aplikasi web independen 5,5/10.** Nilai 8,5 belum didukung bukti. Angka ini penilaian rekayasa, bukan skor benchmark resmi: tidak tersedia ground truth lengkap untuk menghitung precision, recall, atau false positive rate. Tidak ada klaim nol false positive.

## Hasil run yang sebanding

Semua pemindaian memakai Pentest Automation tanpa login, request GET saja, satu origin, tanpa template aktif massal. Target online dibatasi 25 halaman, 120 request, jeda minimum 500 ms; lokal 35 halaman, 160 request, jeda minimum 100 ms. HTTP 429/503 menghentikan run. Rincian lengkap ada di [`audit/multi-target-benchmark.json`](audit/multi-target-benchmark.json).

| Target | Request | Hasil inti |
|---|---:|---|
| PortSwigger Gin and Juice Shop, online | 73 | 0 temuan inti; 6 observasi konfigurasi |
| HCL Altoro Mutual, online | 49 | 1 refleksi HTML kandidat XSS; temuan lain kandidat/konfigurasi |
| Google Firing Range, online | 55 | 0 temuan inti; 6 observasi konfigurasi |
| Pentest Ground DVWA, online | 104 | 3 sinyal SQLi MySQL pada endpoint berbeda; 1 disclosure file lokal terkonfirmasi secara diferensial; kandidat XSS tetap kandidat |
| Pentest Ground DVGA, online | 18 | 0 temuan inti; 10 observasi konfigurasi |
| Pentest Ground RestFlaw, online | 5 | 0 temuan inti; OpenAPI YAML dan satu rute GET ditemukan |
| Pentest Ground GuardianLeaks, online | 14 | 0 temuan inti; kandidat CSRF belum dibuktikan |
| OWASP Juice Shop Docker, lokal | 53 | 1 SQLi SQLite pada `/rest/products/search?q=` terkonfirmasi oleh perbedaan respons input petik, petik ganda, dan baseline |
| VAmPI Docker, lokal | 16 | 2 area sensitif masih kandidat dalam run awal; run ulang khusus VAmPI menemukan respons daftar pengguna dengan field `password` |
| OWASP WebGoat Docker, lokal | 10 | 0 temuan inti; alur utama berada di balik login |

Run ulang khusus VAmPI memakai konfigurasi yang sama dan menghasilkan 11 temuan, termasuk `User-list JSON includes password fields` pada `/users/v1/_debug`; bukti tersimpan dalam [`audit/multi-target-single.json`](audit/multi-target-single.json). Status `confirmed` di sini berarti **field password ada di respons HTTP 200**, bukan telah dibuktikan dapat dibaca pengguna lain atau berisi plaintext. Temuan konfigurasi header/cookie juga memakai `confirmed` untuk kondisi yang diamati, bukan untuk dampak eksploitasi.

## Perubahan yang diuji

- Crawler sekarang memisahkan HTML dari string JavaScript, membatasi variasi URL, memprioritaskan rute API/parameter pencarian, dan membaca rute GET dari OpenAPI JSON/YAML. Ini menghasilkan penemuan endpoint SQLi Juice Shop yang sebelumnya terlewat.
- Detektor SQLi mengenali galat SQLite dengan pembanding baseline dan input seimbang. Pemeriksaan IDOR mensyaratkan parameter identitas dan konteks akses privat; perbedaan ID objek publik tidak lagi dilaporkan sebagai IDOR.
- Cookie infrastruktur yang dikenal tidak diperlakukan sebagai cookie sesi aplikasi. CORS wildcard turun menjadi informasi sampai ada bukti data lintas origin.
- Crawler memblokir path GET yang diketahui dapat mengubah state, termasuk `/createdb` dan `/start_over`. Run 10 target terbaru tidak mengunjungi keduanya; run lama yang sempat mengunjungi path tersebut disimpan di [`audit/multi-target-before-safety.json`](audit/multi-target-before-safety.json) sebagai catatan audit.
- Detektor daftar pengguna melaporkan keberadaan field password tanpa menyimpan nilainya dalam finding. Tes sintetis memastikan nilai rahasia tidak masuk objek finding.

Typecheck dan **300 tes unit lulus**. Uji regresi lab RUY menemukan **150/150** kasus dalam satu run Pentest Automation; tes Rule Engine 50 dan Active Scan 100 juga lulus. Verifikasi paket 1.3.0 lewat UI menghasilkan 150/150 pada Active Scan, Rule Engine, dan Automation; detail flag 1 dan 150 berhasil dibuka. Bukti: [`audit/lab-ui-verification.json`](audit/lab-ui-verification.json). Lab RUY adalah target yang dirancang untuk Interu, sehingga hasilnya tidak dijadikan ukuran akurasi pada aplikasi independen.

Installer [`release/Interu-Setup-1.3.0.exe`](release/Interu-Setup-1.3.0.exe) dan versi portabel [`release/Interu-Portable-1.3.0.exe`](release/Interu-Portable-1.3.0.exe) berhasil dibangun. Versi 1.2.0 dihapus dengan uninstaller resmi (exit 0), lalu 1.3.0 dipasang (exit 0). Aplikasi terpasang melaporkan versi 1.3.0 dan antarmuka Automation beserta 10 kategori tampil; bukti: [`audit/installed-verification.json`](audit/installed-verification.json). Data profil pengguna tidak dihapus oleh uninstaller.

## Batas kemampuan yang masih nyata

Sebagian besar temuan pada 10 target adalah header, cookie, atau kandidat. Crawler tanpa browser tidak menjalankan SPA, GraphQL, dan alur JavaScript kompleks. Pemindaian GET tanpa login tidak menjangkau banyak aksi API, POST, maupun batas kepemilikan akun; WebGoat hampir seluruhnya tertutup login. Rule Engine berjumlah 808 template, namun jumlah template bukan bukti cakupan atau akurasi. Belum ada evaluasi ground truth per endpoint untuk menghitung false positive rate. Prioritas berikutnya: sesi uji terautentikasi dengan kontrol peran, pemeriksaan API aman di luar GET, dan benchmark resmi yang dapat mengukur precision/recall.

## Bukti tambahan

- Baseline sebelum perbaikan: [`LAPORAN-UJI-INDEPENDEN-2026-11-14.md`](LAPORAN-UJI-INDEPENDEN-2026-11-14.md)
- Verifikasi kandidat XSS Altoro: [`audit/altoro-xss-verification.json`](audit/altoro-xss-verification.json)
- Regresi antarmuka lab 150 kasus pada rilis sebelumnya: [`audit/lab-ui-verification.json`](audit/lab-ui-verification.json)

Target yang diuji merupakan aplikasi latihan: [PortSwigger Gin and Juice](https://portswigger.net/burp/documentation/desktop/getting-started/running-your-first-scan), [Pentest Ground](https://pentest-ground.com/), [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), [OWASP WebGoat](https://github.com/WebGoat/WebGoat), dan [VAmPI](https://github.com/erev0s/VAmPI). Pemindaian tidak mencakup platform akun, bug bounty, atau domain di luar daftar di atas.
