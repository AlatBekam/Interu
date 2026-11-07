# 090 — Roadmap

← [041 — Rule Engine](041_rule-engine.md) · [Index](000_index.md)

Dokumen ini menggabungkan checklist dari setiap dokumen fitur menjadi satu rencana berurutan. Rincian tiap tugas ada di bagian **Checklist pengerjaan** pada dokumen fiturnya. ✔ = selesai.

## Prioritas sebelum hari-H (wajib)

Jika ada butir yang belum selesai, juri keamanan kemungkinan akan menemukannya.

1. ✔ ~~**Pasang scope gate pada proxy.**~~ Selesai: host di luar scope di-tunnel tanpa didekripsi atau dicatat. Lihat [011](011_scope-gate.md) dan [021](021_proxy-mitm.md).
2. ✔ ~~**Enkripsi private key CA dan sediakan tombol "Remove CA".**~~ Selesai: key disimpan via safeStorage/DPAPI (+ migrasi key lama), `deleteCA()` + tombol Remove CA. Lihat [012](012_root-ca-dan-sertifikat.md).
3. ✔ ~~**Perketat `setCertificateVerifyProc`.**~~ Selesai: `cb(0)` hanya untuk cert ber-issuer Interu CA; selain itu `cb(-3)` (verifikasi normal). Lihat [013](013_hardening-electron.md).
4. ✔ ~~**Perbaiki README.**~~ Selesai: status modul dan API preload sudah sesuai dengan kode.
5. ✔ ~~**Hapus semua simulasi.**~~ Selesai: mode simulasi dan halaman data palsu (Dashboard, Firewall Rules, Reports) dihapus; semua halaman live-only. Lihat [030](030_operations.md).
6. **Isi Authorized scope sebelum demo.** Dengan scope kosong, history proxy, scanner, dan probe aktif tidak akan menghasilkan apa-apa.

## Fase 1 — Fondasi keamanan

| Tugas | Status | Dokumen |
|---|---|---|
| Scope gate di proxy, scanner, dan `ruy:http`; dukungan CIDR; test unit | ✔ | [011](011_scope-gate.md) |
| Dukungan IPv6 dan port pada entri scope IP; pengecekan ulang tunnel yang sudah terbuka saat scope berubah | | [011](011_scope-gate.md) |
| Audit log setiap penolakan scope | | [011](011_scope-gate.md) |
| Enkripsi key CA (safeStorage/DPAPI) + `deleteCA()`/Remove CA | ✔ | [012](012_root-ca-dan-sertifikat.md) |
| ACL folder `ca/`, panduan uninstall trust | | [012](012_root-ca-dan-sertifikat.md) |
| `sandbox:true` diaktifkan | ✔ | [013](013_hardening-electron.md) |
| Batasi `rejectUnauthorized:false` hanya untuk host dalam scope | ✔ | [013](013_hardening-electron.md) |

## Fase 2 — Verifikasi & perbaikan Web Security Suite

| Tugas | Status | Dokumen |
|---|---|---|
| Uji proxy dalam dan luar scope (hook `RUY_PROXY_TEST` + `RUY_PROXY_SCOPE`) | ✔ | [021](021_proxy-mitm.md) |
| Uji manual di UI: intercept edit/drop, Export CA, Send to Repeater/Intruder | | [021](021_proxy-mitm.md) |
| Samakan tipe `ProxyLogEntry.kind` (`'https-tunnel'` vs `'https'`) | | [021](021_proxy-mitm.md) |
| Uji parsing raw request serta request live dengan dan tanpa scope | | [022](022_repeater.md) |
| Putuskan substitusi `§…§` (`/g` atau satu penanda); pertimbangkan Pitchfork/Cluster bomb | | [023](023_intruder.md) |
| Uji wordlist discovery dan filter hit | | [024](024_target-discovery.md) |
| Uji round-trip encode/decode, UTF-8, dan input invalid | | [025](025_decoder.md) |
| Uji kebenaran `lineDiff` | | [026](026_comparer.md) |
| Isi token Sequencer otomatis dari respons yang tertangkap (saat ini operator menempel manual) | | [027](027_sequencer.md) |

## Fase 3 — Operations & Detection

Urutan ini mengikuti dependensi data: scanner menghasilkan aset, Rule Engine menghasilkan temuan, lalu temuan dipakai oleh halaman berikutnya. Dashboard, Firewall Rules, dan Reports lama sudah dihapus; butir 6 dan 7 di bawah adalah **halaman baru** yang dibangun dari data nyata.

| # | Tugas | Status | Dokumen |
|---|---|---|---|
| 1 | TCP connect scan via `ruy:scan:tcp` (scope-gated), parsing CIDR, banner grab | ✔ | [032](032_network-scanner.md) |
| 2 | Rule Engine: 27 template, Suspected/Confirmed, probe aktif scope-gated | ✔ | [041](041_rule-engine.md) |
| 3 | Vulnerabilities dari store findings (live saja) | ✔ | [033](033_vulnerabilities.md) |
| 4 | Rule Engine: naikkan Suspected → Confirmed saat terbukti, baseline soft-404, extractor, template eksternal | | [041](041_rule-engine.md) |
| 5 | Vulnerabilities: status kerja per temuan, filter Confidence, bukti lengkap | | [033](033_vulnerabilities.md) |
| 6 | **Halaman baru:** ringkasan eksposur dari store findings dan hasil scan nyata (bila Exposure Monitor belum cukup) | | [034](034_threat-monitor.md) |
| 7 | **Halaman baru:** laporan dari findings Confirmed + export PDF; `operatorName` dibaca via `useSettings` | | — |
| 8 | Exposure Monitor diberi data dari `proxy.onLog`, severity dari Rule Engine | | [034](034_threat-monitor.md) |
| 9 | **Halaman baru:** ekspor rule Windows Firewall ke format netsh dulu, apply ke sistem belakangan (dengan konfirmasi + hak admin) | | — |
| 10 | Settings: editor scope, export/import pengaturan | | [037](037_settings.md) |
| 11 | UI industrial dengan token peran, guard test, dan audit e2e | ✔ | [092](092_panduan-tampilan.md) |

## Fase 4 — Lintas fitur

- **Audit log** untuk setiap request live, scan, perubahan rule, dan penolakan scope.
- **Test unit:** ✔ vitest sudah terpasang (`npm test`) untuk scope dan rule cookie. Sequencer (`src/shared/tokens.ts`) dan konsistensi UI (`src/renderer/src/styles`) sudah punya tes. Berikutnya: `lineDiff`, pasangan Decoder, dan template rules lainnya.
- **CI** (GitHub Actions) yang menjalankan `typecheck` dan `npm test`.
- **Pemetaan MITRE ATT&CK** dan Attack Path Graph, sesuai info.txt §5. Field `mitre` sudah ada di sebagian template.
- **Konsistensi branding:** sisa nama "RUY" (`window.ruy`, `ruy:*`, `ruy.v1.*`) masih dipertahankan. Jika diganti, perlu migrasi localStorage.
