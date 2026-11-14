# Interu 1.4.0

Interu adalah aplikasi desktop Windows untuk pengujian keamanan jaringan dan web oleh operator yang memiliki izin. Aplikasi dibuat dengan Electron, React, dan TypeScript. Pemindaian otomatis memakai **aturan dan pemeriksaan deterministik**; aplikasi tidak memakai model AI atau layanan AI.

## Mulai menggunakan

1. Jalankan `release/Interu-Setup-1.4.0.exe` untuk memasang aplikasi, atau `release/Interu-Portable-1.4.0.exe` untuk menjalankannya tanpa instalasi.
2. Tambahkan host yang memang diizinkan ke **Scope**. Scope kosong pada awal penggunaan; operasi jaringan ke target memerlukan host dalam Scope.
3. Pilih modul sesuai kebutuhan. Untuk satu alur otomatis, buka **Pentest Automation**, isi URL target dan batas pemindaian, lalu jalankan.
4. Tinjau hasil di **Operations > Vulnerabilities**. Klik temuan untuk melihat bukti request/response dan, pada lab RUY, flag yang dikembalikan target.

Installer 1.4.0 dibuat untuk Windows x64. Uninstaller tidak menghapus profil pengguna. Paket belum ditandatangani dengan sertifikat penerbit kode.

## Modul

| Bagian | Kemampuan yang tersedia |
|---|---|
| Web Security Suite | Proxy HTTP/HTTPS dengan intercept, browser bawaan, Repeater, Intruder, Target/Site Map, Crawler, Active Scan, Decoder, Comparer, dan Sequencer. |
| Active Scan | Crawl dan probe GET terbatas untuk sinyal SQLi, XSS, LFI, XXE, SSTI, RCE, SSRF, IDOR, akses sensitif, serta CSRF. Tingkat keyakinan mengikuti bukti tiap pemeriksaan; sinyal kontekstual tetap kandidat. |
| Rule Engine | **808 template data**: 28 port/banner, 47 HTTP pasif, dan 733 HTTP aktif. Matcher status/teks/regex/waktu/port/service/DSL, extractor, interpolasi variabel, pembanding soft-404, dan korelasi temuan. Detektor respons JSON daftar pengguna yang memuat field `password` ditambahkan di luar jumlah template tersebut. |
| Pentest Automation | Satu run yang menggabungkan crawl, analisis pasif, probe parameter, dan pemeriksaan template aktif yang dipilih operator. Opsi browser menjelajah halaman satu origin lewat Proxy dan memasukkan URL hasilnya ke crawler. Opsi akun uji mencoba registrasi dan login berbasis aturan bila form yang sesuai tersedia. |
| Operations | Network Scanner TCP connect dengan banner, Exposure Monitor, dan daftar Vulnerabilities yang membuka detail bukti. |
| Authenticated scan | Operator login manual lewat browser bawaan Proxy, lalu menyalin header `Cookie` dari request setelah login ke panel Authenticated scan. Header dipakai pada origin yang sama oleh Crawler, Active Scan, Rule Engine aktif, dan Pentest Automation. |

Temuan terkonfirmasi pada Rule Engine dapat menampilkan saran verifikasi dan perbaikan melalui advisor Attack/Defense. Antarmuka menyediakan tema Dark dan Light di Settings.

Pemeriksaan otomatis tidak membuktikan semua kategori OWASP Top 10. Tabel OWASP pada layar Automation menyebut sinyal aturan serta pemeriksaan manual yang masih diperlukan; tabel itu bukan sertifikasi cakupan.

## Eksplorasi browser dan akun uji otomatis

Di **Pentest Automation**, isi URL target dalam Scope lalu pilih salah satu tombol:

- **Start automation**: pemindaian seperti sebelumnya tanpa browser tambahan.
- **Explore browser + run**: Interu membuka browser bawaan melalui Proxy, menjelajah maksimal 12 halaman GET pada origin target, mencatat form login/register dan URL yang ditemukan, lalu menjalankan scanner dengan URL itu sebagai seed tambahan. Halaman JavaScript dapat dirender oleh browser pada tahap ini.
- **Explore + create test account + run**: selain eksplorasi, Interu membuat identitas sementara acak dan mencoba form registrasi POST pada origin yang sama, kemudian mencoba form login yang ditemukan. Interu tidak meminta user mengetik kredensial. Jika cookie browser berubah, cookie yang berlaku untuk URL target dihubungkan ke Automation di proses utama. Nilai cookie dan kata sandi sementara tidak dikembalikan ke UI.

Form yang memerlukan CAPTCHA, MFA, persetujuan kotak centang wajib, verifikasi email, SSO lintas origin, atau field yang tidak dikenal dapat menghentikan alur akun. Perubahan cookie **bukan bukti login berhasil**; panel menampilkan status percobaan dan temuan hanya berasal dari respons nyata. Gunakan opsi pembuatan akun hanya pada target yang mengizinkan akun uji otomatis. Opsi ini mengirim POST registrasi/login dan dapat membuat data akun pada target.

## Login lewat browser Interu, lalu scan dengan sesi

1. Tambahkan host target ke **Scope**. Buka **Proxy**, jalankan proxy, lalu pilih **Open Browser**.
2. Login manual memakai akun uji pada situs target di browser bawaan. Setelah login, pilih request ke halaman yang membutuhkan sesi pada riwayat Proxy dan salin header **`Cookie: ...` dari request** tersebut. Header `Set-Cookie` pada response bukan format yang ditempel ke pemindai.
3. Pada **Authenticated scan**, isi **Credential origin** sesuai URL target, termasuk `http` atau `https`, host, dan port. Tempel baris `Cookie: ...` di **Headers**, lalu klik **Apply credentials**. Token `Authorization: Bearer ...` juga didukung bila situs memakai token.
4. Jalankan **Crawler**, **Active Scan**, **Rule Engine active checks**, atau **Pentest Automation** pada target dalam Scope. Header sesi ditambahkan ke request pada origin yang cocok.
5. Bila muncul **session expired**, login lagi, tempel header baru, klik **Apply credentials**, lalu **Refresh** sebelum menjalankan ulang scan.

Pada alur manual, cookie masih perlu disalin dari riwayat Proxy. Pada opsi akun uji otomatis di Automation, cookie yang diamati browser dihubungkan secara internal tanpa ditempel. Header sesi disimpan hanya di memori proses utama selama aplikasi berjalan dan tidak disimpan ke pengaturan lokal. Gunakan akun uji karena pemindaian mengirim request atas nama akun tersebut.

## Perubahan pada 1.4.0

- Browser discovery lewat Proxy memasukkan halaman yang dirender Chromium sebagai seed tambahan untuk Automation; form dicatat sebagai permukaan, bukan kerentanan.
- Opsi akun uji mencoba registrasi/login pada form POST satu origin dengan kredensial acak, dan hanya memakai cookie yang diamati setelah percobaan tersebut. Jika alur gagal, sesi lama dibersihkan agar scan tidak diam-diam memakai kredensial sebelumnya.
- Navigasi discovery dibatasi satu origin, maksimal 12 halaman dari antarmuka, dengan jeda minimum 500 ms antarhalaman. Scanner tetap memakai batas request, jeda, dan durasi yang dipilih operator.

## Perubahan pada 1.3.0

- Crawler memisahkan tautan HTML dari string JavaScript, membatasi variasi URL, memprioritaskan URL dengan parameter yang relevan, serta mengekstrak rute GET dari OpenAPI JSON/YAML.
- Deteksi SQLi mengenali pola galat SQLite dan memakai respons baseline serta input penyeimbang sebagai kontrol.
- Probe IDOR menuntut parameter identitas dan konteks akses yang sesuai. Perubahan ID objek publik saja tidak cukup untuk menyatakan IDOR.
- Cookie infrastruktur yang dikenal tidak dilaporkan sebagai cookie sesi aplikasi. CORS wildcard dicatat sebagai informasi sampai ada bukti paparan data.
- Crawler melewati path GET yang diketahui dapat mengubah state, termasuk `/createdb` dan `/start_over`.
- Detektor daftar pengguna melaporkan keberadaan field `password` tanpa menyimpan isinya dalam objek temuan.

## Bukti pengujian

- `npm run typecheck` dan `npm test` lulus pada sumber 1.4.0: **300 tes berjalan lulus**, sementara tes live yang memerlukan target dan variabel lingkungan khusus dilewati pada run standar.
- Tes end-to-end akun lokal: form registrasi dan login dikirim oleh browser, request scanner membaca halaman privat dengan cookie sesi, dan kata sandi sementara tidak muncul di UI. Bukti: [`audit/browser-account-verification.json`](audit/browser-account-verification.json).
- Paket Windows 1.3.0 diuji melalui antarmuka pada lab RUY Docker: Active Scan, Rule Engine, dan Pentest Automation masing-masing menampilkan **150/150** kasus; detail flag 1 dan 150 dapat dibuka. Hasil: [`audit/lab-ui-verification.json`](audit/lab-ui-verification.json).
- Sepuluh aplikasi latihan independen diuji dengan Pentest Automation terbatas **tanpa header sesi login**, terdiri dari tujuh target online dan tiga target Docker lokal. Bukti mentah: [`audit/multi-target-benchmark.json`](audit/multi-target-benchmark.json). Run khusus VAmPI setelah aturan respons JSON ditambahkan: [`audit/multi-target-single.json`](audit/multi-target-single.json).
- Pada run tersebut, scanner mencatat tiga sinyal SQLi MySQL dan satu disclosure file pada DVWA online, satu sinyal SQLi SQLite pada Juice Shop lokal, serta keberadaan field `password` pada respons JSON VAmPI lokal. Refleksi HTML di Altoro tetap diberi label kandidat XSS. Temuan header/cookie adalah kondisi yang diamati, bukan bukti dampak eksploitasi.
- Installer 1.4.0 telah dipasang. Pemeriksaan aplikasi terpasang melaporkan versi 1.4.0, bridge modul tersedia, dan layar Automation memuat 10 kategori OWASP: [`audit/installed-verification.json`](audit/installed-verification.json).
- Run langsung melalui antarmuka Automation aplikasi terpasang 1.4.0 pada lab RUY lokal selesai dengan 894 request, 40 halaman, 175 temuan berbagai tingkat keyakinan, dan 0 kesalahan transport. Angka temuan bukan jumlah kerentanan unik: [`audit/installed-automation-live-2026-11-14.json`](audit/installed-automation-live-2026-11-14.json).
- Run ulang browser pada 10 target latihan terdokumentasi di [`audit/ten-browser-benchmark.json`](audit/ten-browser-benchmark.json). Tidak ada form registrasi yang cocok dalam run itu, dan jumlah temuan inti terkonfirmasi tidak bertambah. Rangkuman perbandingan: [`LAPORAN-PERBANDINGAN-10-TARGET-1.4.0.md`](LAPORAN-PERBANDINGAN-10-TARGET-1.4.0.md).

Lab RUY memang dirancang untuk menguji Interu. Hasil 150/150 menunjukkan regresi internal berfungsi, bukan tingkat deteksi pada seluruh aplikasi nyata. Belum ada ground truth lengkap per endpoint untuk menghitung precision, recall, atau false positive rate. Uji 10 target awal tidak memakai sesi login. Browser discovery 1.4.0 dapat merender halaman JavaScript, tetapi probe kerentanan otomatis masih berfokus pada GET; alur POST/GraphQL dan logika aplikasi kompleks dapat terlewat.

## Batas pemindaian

Pemindaian aktif melalui modul Interu memeriksa Scope yang ditentukan operator. Proxy meneruskan traffic di luar Scope tanpa inspeksi; koneksi HTTPS di luar Scope dibuat sebagai tunnel tanpa dekripsi. Pentest Automation memakai satu origin, batas request dan waktu, serta menghentikan run bila server merespons 429/503 atau scope berubah. Gunakan hanya pada sistem milik sendiri atau target yang secara jelas mengizinkan pengujian. Untuk layanan publik, sesuaikan laju dan modul dengan aturan pemilik target.

Proxy, Repeater, Intruder, dan pemindaian aktif mengirim traffic nyata. Decoder, Comparer, dan Sequencer bekerja lokal. CA untuk proxy HTTPS dibuat lokal; browser bawaan Interu mempercayainya untuk sesi proxy, sedangkan browser eksternal memerlukan ekspor dan pemasangan CA oleh operator.

## Bangun dari sumber

Prasyarat: Windows x64, Node.js 20 atau lebih baru, dan npm. Pengguna installer tidak memerlukan instalasi Node.js terpisah.

```powershell
npm install
npm run typecheck
npm test
npm run dist
```

`npm run dev` membuka mode pengembangan. `npm run build` membuat output produksi di `out/`. `npm run dist` menghasilkan installer dan versi portabel di `release/`. Konfigurasi paket terdapat di [`electron-builder.yml`](electron-builder.yml).

Kode utama berada di `src/main/` (proses Electron dan request jaringan), `src/shared/` (aturan, crawler, probe, tipe), `src/preload/` (jembatan IPC), serta `src/renderer/` (antarmuka). Lab Docker berada di `lab/`; testcase live di `testcase/`. Data pengaturan dan temuan pengguna disimpan lokal; **Settings > Local data > Reset local data** menghapus data lokal aplikasi.
