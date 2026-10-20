# 090 — Roadmap

← [037 — Settings](037_settings.md) · [Index](000_index.md)

Dokumen ini menggabungkan checklist dari setiap dokumen fitur menjadi satu rencana berurutan. Rincian tiap tugas ada di bagian **Checklist pengerjaan** pada dokumen fiturnya.

## Prioritas sebelum hari-H (wajib)

Jika ada butir yang belum selesai, juri keamanan kemungkinan akan menemukannya.

1. **Pasang scope gate pada proxy.** Tambahkan pemanggilan `hostInScope` di `handleRequest` dan kirim daftar scope ke proxy. Lihat [011](011_scope-gate.md) dan [021](021_proxy-mitm.md).
2. **Enkripsi private key CA dan sediakan tombol "Remove CA".** Lihat [012](012_root-ca-dan-sertifikat.md).
3. **Perketat `setCertificateVerifyProc`.** Terima hanya sertifikat yang ditandatangani Interu CA, bukan `cb(0)` untuk semua sertifikat. Lihat [013](013_hardening-electron.md).
4. **Perbaiki README.** Klaim bahwa Proxy, Repeater, Intruder, dan Target hanya "canned demo" salah, karena modul-modul itu nyata. Lihat [001](001_ringkasan-proyek.md).
5. **Beri label jujur pada setiap halaman simulasi.** Lihat [030](030_operations.md).

## Fase 1 — Fondasi keamanan

| Tugas | Dokumen |
|---|---|
| Scope gate di proxy + pesan penolakan seragam + audit log penolakan | [011](011_scope-gate.md) |
| Enkripsi key CA, `deleteCA()`, ACL folder `ca/`, panduan uninstall trust | [012](012_root-ca-dan-sertifikat.md) |
| Evaluasi `sandbox:true`, batasi `rejectUnauthorized:false` ke host dalam scope | [013](013_hardening-electron.md) |

## Fase 2 — Verifikasi & perbaikan Web Security Suite

| Tugas | Dokumen |
|---|---|
| Uji end-to-end proxy: HTTP/HTTPS, intercept edit/drop, Export CA, Send to Repeater/Intruder | [021](021_proxy-mitm.md) |
| Uji parsing raw request serta mode live dengan dan tanpa scope | [022](022_repeater.md) |
| Putuskan substitusi `§…§` (`/g` atau satu penanda); pertimbangkan Pitchfork/Cluster bomb | [023](023_intruder.md) |
| Uji wordlist discovery dan filter hit | [024](024_target-discovery.md) |
| Uji round-trip encode/decode, UTF-8, dan input invalid | [025](025_decoder.md) |
| Uji kebenaran `lineDiff` | [026](026_comparer.md) |
| Ambil token dari respons yang tertangkap, bukan generator lokal | [027](027_sequencer.md) |
| Samakan tipe `ProxyLogEntry.kind` (`'https-tunnel'` vs `'https'`) | [021](021_proxy-mitm.md) |

## Fase 3 — Operations: dari simulasi ke nyata

Urutan ini mengikuti dependensi data: scanner menghasilkan aset, Rule Engine menghasilkan temuan, lalu temuan dipakai oleh dashboard dan laporan.

| # | Tugas | Dokumen |
|---|---|---|
| 1 | TCP connect scan via IPC `ruy:scan:tcp` (dengan scope gate), parsing CIDR, banner grab | [032](032_network-scanner.md) |
| 2 | Rule Engine: temuan Suspected/Confirmed + bukti, pencocokan banner → CVE | [033](033_vulnerabilities.md) |
| 3 | Threat Monitor diberi data dari `proxy.onLog`, severity dari Rule Engine | [034](034_threat-monitor.md) |
| 4 | Dashboard mengagregasi hasil scan dan temuan nyata | [031](031_dashboard.md) |
| 5 | Reports dari temuan Confirmed + export PDF; `operatorName` dibaca via `useSettings` | [036](036_reports.md) |
| 6 | Firewall: export ke format netsh dulu, apply ke sistem belakangan (dengan konfirmasi + hak admin) | [035](035_firewall.md) |
| 7 | Settings: editor scope, label "Mode" dinamis, export/import pengaturan | [037](037_settings.md) |

## Fase 4 — Lintas fitur

- **Audit log** untuk setiap request live, scan, perubahan rule, dan penolakan scope.
- **Test unit** untuk `hostInScope`, `lineDiff`, `shannonBitsPerChar`, dan pasangan Decoder (belum ada framework test; Vitest cocok dengan Vite).
- **CI** (GitHub Actions) yang menjalankan `typecheck` dan test.
- **Pemetaan MITRE ATT&CK** dan Attack Path Graph, sesuai info.txt §5.
- **Konsistensi branding:** sisa nama "RUY" (`window.ruy`, `ruy:*`, `ruy.v1.*`) masih dipertahankan. Jika diganti, perlu migrasi localStorage.
