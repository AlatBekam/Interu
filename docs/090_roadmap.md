# 090 — Roadmap

← [041 — Rule Engine](041_rule-engine.md) · [Index](000_index.md)

Dokumen ini menggabungkan checklist dari setiap dokumen fitur menjadi satu rencana berurutan. Rincian tiap tugas ada di bagian **Checklist pengerjaan** pada dokumen fiturnya. ✔ = selesai.

## Prioritas sebelum hari-H (wajib)

Jika ada butir yang belum selesai, juri keamanan kemungkinan akan menemukannya.

1. ✔ ~~**Pasang scope gate pada proxy.**~~ Selesai: host di luar scope di-tunnel tanpa didekripsi atau dicatat. Lihat [011](011_scope-gate.md) dan [021](021_proxy-mitm.md).
2. **Enkripsi private key CA dan sediakan tombol "Remove CA".** Lihat [012](012_root-ca-dan-sertifikat.md).
3. **Perketat `setCertificateVerifyProc`.** Terima hanya sertifikat yang ditandatangani Interu CA, bukan `cb(0)` untuk semua sertifikat. Lihat [013](013_hardening-electron.md).
4. ✔ ~~**Perbaiki README.**~~ Selesai: status modul dan API preload sudah sesuai dengan kode.
5. **Beri label jujur pada setiap halaman simulasi.** Dashboard, Threat Monitor, Firewall, dan Reports masih memakai data contoh. Lihat [030](030_operations.md).
6. **Isi Authorized scope sebelum demo.** Dengan scope kosong, history proxy, scanner, dan probe aktif tidak akan menghasilkan apa-apa.

## Fase 1 — Fondasi keamanan

| Tugas | Status | Dokumen |
|---|---|---|
| Scope gate di proxy, scanner, dan `ruy:http`; dukungan CIDR; test unit | ✔ | [011](011_scope-gate.md) |
| Dukungan IPv6 dan port pada entri scope IP; pengecekan ulang tunnel yang sudah terbuka saat scope berubah | | [011](011_scope-gate.md) |
| Audit log setiap penolakan scope | | [011](011_scope-gate.md) |
| Enkripsi key CA, `deleteCA()`, ACL folder `ca/`, panduan uninstall trust | | [012](012_root-ca-dan-sertifikat.md) |
| Evaluasi `sandbox:true` | | [013](013_hardening-electron.md) |
| Batasi `rejectUnauthorized:false` hanya untuk host dalam scope | ✔ | [013](013_hardening-electron.md) |

## Fase 2 — Verifikasi & perbaikan Web Security Suite

| Tugas | Status | Dokumen |
|---|---|---|
| Uji proxy dalam dan luar scope (hook `RUY_PROXY_TEST` + `RUY_PROXY_SCOPE`) | ✔ | [021](021_proxy-mitm.md) |
| Uji manual di UI: intercept edit/drop, Export CA, Send to Repeater/Intruder | | [021](021_proxy-mitm.md) |
| Samakan tipe `ProxyLogEntry.kind` (`'https-tunnel'` vs `'https'`) | | [021](021_proxy-mitm.md) |
| Uji parsing raw request serta mode live dengan dan tanpa scope | | [022](022_repeater.md) |
| Putuskan substitusi `§…§` (`/g` atau satu penanda); pertimbangkan Pitchfork/Cluster bomb | | [023](023_intruder.md) |
| Uji wordlist discovery dan filter hit | | [024](024_target-discovery.md) |
| Uji round-trip encode/decode, UTF-8, dan input invalid | | [025](025_decoder.md) |
| Uji kebenaran `lineDiff` | | [026](026_comparer.md) |
| Ambil token dari respons yang tertangkap, bukan generator lokal | | [027](027_sequencer.md) |

## Fase 3 — Operations & Detection: dari simulasi ke nyata

Urutan ini mengikuti dependensi data: scanner menghasilkan aset, Rule Engine menghasilkan temuan, lalu temuan dipakai oleh dashboard dan laporan.

| # | Tugas | Status | Dokumen |
|---|---|---|---|
| 1 | TCP connect scan via `ruy:scan:tcp` (scope-gated), parsing CIDR, banner grab | ✔ | [032](032_network-scanner.md) |
| 2 | Rule Engine: 27 template, Suspected/Confirmed, probe aktif scope-gated | ✔ | [041](041_rule-engine.md) |
| 3 | Vulnerabilities mode Live dari store findings | ✔ | [033](033_vulnerabilities.md) |
| 4 | Rule Engine: naikkan Suspected → Confirmed saat terbukti, baseline soft-404, extractor, template eksternal | | [041](041_rule-engine.md) |
| 5 | Vulnerabilities: status kerja per temuan, filter Confidence, bukti lengkap | | [033](033_vulnerabilities.md) |
| 6 | Dashboard membaca store findings dan hasil scan nyata | | [031](031_dashboard.md) |
| 7 | Reports dari findings Confirmed + export PDF; `operatorName` dibaca via `useSettings` | | [036](036_reports.md) |
| 8 | Threat Monitor diberi data dari `proxy.onLog`, severity dari Rule Engine | | [034](034_threat-monitor.md) |
| 9 | Firewall: export ke format netsh dulu, apply ke sistem belakangan (dengan konfirmasi + hak admin) | | [035](035_firewall.md) |
| 10 | Settings: editor scope, label "Mode" dinamis, export/import pengaturan | | [037](037_settings.md) |

## Fase 4 — Lintas fitur

- ✔ **Audit log** untuk setiap request live, scan, proxy, dan penolakan scope/RoE ([051](051_roe-audit-log.md)). Berikutnya: tanda tangan digital head hash dan rotasi log proxy.
- ✔ **Paket bukti, retest, Attack Path** ([052](052_paket-bukti.md), [053](053_retest.md), [054](054_attack-path.md)). Berikutnya: Reports memakai bukti + hasil retest, ekspor zip, ID ATT&CK di semua template.
- **Test unit:** ✔ vitest sudah terpasang (`npm test`) untuk scope dan rule cookie. Berikutnya: `lineDiff`, `shannonBitsPerChar`, pasangan Decoder, dan template rules lainnya.
- **CI** (GitHub Actions) yang menjalankan `typecheck` dan `npm test`.
- 🟡 **Pemetaan MITRE ATT&CK:** Attack Path Graph sudah ada; taktik masih heuristik karena baru 3 template yang punya ID teknik.
- **Konsistensi branding:** sisa nama "RUY" (`window.ruy`, `ruy:*`, `ruy.v1.*`) masih dipertahankan. Jika diganti, perlu migrasi localStorage.
