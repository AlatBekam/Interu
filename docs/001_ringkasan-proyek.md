# 001 — Ringkasan Proyek

← [000 — Index Dokumentasi Interu](000_index.md) · [Index](000_index.md) · [002 — Setup & Build](002_setup-dan-build.md) →

## Apa itu Interu

**Interu — Cyber Operations** (brand lama internal: **RUY**) adalah aplikasi
**desktop Windows** (Electron + React + TypeScript) yang menggabungkan beberapa
alat keamanan siber dalam satu workstation lokal. Dibuat oleh **RUY Cybersecurity
Team** untuk **Kartika Cyber Hackathon 2026 — Kategori 01: Penindakan**.

Satu aplikasi menyatukan:

- **Web Security Suite** gaya Burp Suite (Proxy, Repeater, Intruder, Target,
  Decoder, Comparer, Sequencer).
- **Operations** (Dashboard, Network Scanner, Vulnerabilities, Threat Monitor,
  Firewall Rules).
- **Detection** (Rule Engine gaya Nuclei, route `/detection`).
- **Analysis / Reporting**.

Identitas kerja produk: *legal-by-design* — fitur yang mengirim atau menangkap
trafik nyata dibatasi oleh **Scope / Authorization** (hanya host/IP/CIDR yang
didaftarkan operator yang boleh dikenai aksi "live"). Gate berlaku di proses main
untuk `ruy:http`, `ruy:scan:tcp`, dan proxy (lihat [011](011_scope-gate.md)).

## Masalah yang diselesaikan

- Menyediakan alat uji keamanan web (proxy intercept, repeater, fuzzing) **mandiri
  / buatan Indonesia** dalam satu aplikasi desktop, tanpa backend dan tanpa
  ketergantungan layanan luar.
- Menegakkan **batas otorisasi** secara teknis: request/scan "live" ditolak jika
  host target tidak ada di Scope, dan proxy hanya mendekripsi/mencatat host in-scope
  (lihat [011 — Scope Gate](011_scope-gate.md)).
- Menyediakan **mode Simulation** untuk latihan aman memakai data contoh.

## Kategori Hackathon

Kartika Cyber Hackathon 2026 — **Kategori 01: Penindakan** (Offensive Tech).
Produk versi `1.0.0`.

## Kelompok fitur

| Kelompok | Kode | Status | Isi |
|---|---|---|---|
| Fondasi keamanan | 01x | Campur | Scope gate, Root CA & sertifikat, hardening Electron |
| Web Security Suite | 02x | ✅ Nyata | Proxy MITM, Repeater, Intruder, Target, Decoder, Comparer, Sequencer |
| Operations | 03x | Campur | **Nyata:** Network Scanner (TCP connect, [032](032_network-scanner.md)), Vulnerabilities mode Live. **Simulasi:** Dashboard, Threat Monitor, Firewall, Reports, Settings |
| Detection | 04x | ✅ Nyata | Rule Engine (template gaya Nuclei, [041](041_rule-engine.md)); temuan dari scanner + respons proxy |

**Catatan.** Versi README lama menyebut Proxy, Repeater, Intruder, dan Target
sebagai *canned demo data*. Kode menunjukkan keempatnya memakai jembatan nyata
`window.ruy` (`src/preload/index.ts`) dan mengirim trafik HTTP(S) sungguhan lewat
`src/main/http.ts` / `src/main/proxy.ts`. README sekarang sudah sesuai (tabel modul
menandai *Live/REAL*).

## Tech stack

| Lapisan | Teknologi |
|---|---|
| Runtime desktop | Electron `^33.0.0` |
| UI | React `^18.3.1` + React Router `^6.26.2` (HashRouter) |
| Bahasa | TypeScript `^5.6.2` |
| Bundler / dev | Vite `^5.4.8` via electron-vite `^2.3.0` |
| TLS MITM / sertifikat | node-forge `^1.3.1` |
| Packaging | electron-builder `^25.1.8` (NSIS installer + portable, Windows x64) |
| Test | vitest `^2.1.9` (`npm test`, lihat [002](002_setup-dan-build.md)) |
| Ikon build | @resvg/resvg-js, png-to-ico (lihat `scripts/generate-icons.mjs`) |

Tidak ada database atau server: semua state renderer disimpan di `localStorage`
(namespace `ruy.v1.`, lihat `src/renderer/src/store/store.ts`).
