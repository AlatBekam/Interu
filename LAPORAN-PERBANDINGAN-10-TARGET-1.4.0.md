# Perbandingan evaluasi Interu pada 10 target latihan

Tanggal: 14 November 2026. Run awal tersimpan di `audit/multi-target-benchmark.json`; run dengan penjelajahan browser 1.4.0 di `audit/ten-browser-benchmark.json`. Ketiga target lokal berjalan di Docker. Tujuh target online adalah aplikasi latihan yang sengaja disediakan untuk pengujian. Angka **temuan** di bawah mencakup sinyal header, cookie, dan kandidat; angka itu bukan jumlah kerentanan terkonfirmasi.

| Target | Lingkungan | Request run browser | Temuan awal → browser | Hasil penting |
|---|---|---:|---:|---|
| Gin and Juice Shop | Online | 73 | 6 → 6 | Tidak ada temuan inti baru |
| Altoro Mutual | Online | 49 | 12 → 12 | Refleksi HTML tetap kandidat XSS |
| Google Firing Range | Online | 120 | 6 → 7 | Run berhenti pada batas request; tidak ada temuan inti baru |
| DVWA, Pentest Ground | Online | 104 | 20 → 21 | Tiga sinyal SQLi MySQL dan satu disclosure file tetap teramati |
| DVGA, Pentest Ground | Online | 18 | 10 → 10 | Tidak ada temuan inti baru |
| RestFlaw, Pentest Ground | Online | 5 | 7 → 7 | Tidak ada temuan inti baru |
| GuardianLeaks, Pentest Ground | Online | 14 | 15 → 15 | Tidak ada temuan inti baru |
| OWASP Juice Shop | Docker lokal | 53 | 4 → 4 | Satu sinyal SQLi SQLite tetap teramati |
| VAmPI | Docker lokal | 16 | 10 → 11 | Tambahan deteksi field `password` di JSON daftar pengguna |
| OWASP WebGoat | Docker lokal | 10 | 7 → 7 | Tidak ada temuan inti baru |

Browser membuka halaman dalam origin target dan mencatat form. Pada run ini tidak ditemukan form registrasi yang cocok untuk alur akun otomatis, sehingga **tidak ada login otomatis yang berhasil dibuktikan pada 10 target**. Tes end-to-end lokal terpisah di `audit/browser-account-verification.json` membuktikan browser dapat membuat akun uji, login, dan memberi scanner akses ke halaman privat pada aplikasi uji yang formnya kompatibel. Kata sandi sementara dan cookie sesi tidak muncul di UI atau riwayat Proxy pada tes tersebut.

Hasil 10 target menunjukkan penjelajahan browser belum meningkatkan jumlah temuan inti terkonfirmasi pada sampel ini. Tambahan satu temuan VAmPI berasal dari detektor respons JSON yang juga ada pada run awal sebelum fitur browser. Karena belum ada ground truth lengkap per endpoint, data ini tidak cukup untuk menghitung precision, recall, atau false positive rate. Pengujian perlu dilanjutkan pada alur POST, GraphQL, SPA, dan autentikasi yang lebih beragam; hasil di sini tidak menyatakan keamanan target yang tidak menghasilkan temuan.

Regresi lab RUY tetap terpisah dari evaluasi ini: paket 1.3.0 diuji melalui UI pada Active Scan, Rule Engine, dan Pentest Automation masing-masing 150/150 (`audit/lab-ui-verification.json`); tes live sumber 1.4.0 juga menemukan 150/150 (`testcase/interu50-live.test.ts`). Lab itu dirancang untuk Interu dan tidak dipakai sebagai ukuran kinerja pada aplikasi independen.
