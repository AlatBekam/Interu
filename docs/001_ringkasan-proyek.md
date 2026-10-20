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
- **Analysis / Reporting**.

Identitas kerja produk: *legal-by-design* — fitur yang mengirim trafik nyata
dibatasi oleh **Scope / Authorization** (hanya host yang didaftarkan operator yang
boleh dikenai aksi "live").

## Masalah yang diselesaikan

- Menyediakan alat uji keamanan web (proxy intercept, repeater, fuzzing) **mandiri
  / buatan Indonesia** dalam satu aplikasi desktop, tanpa backend dan tanpa
  ketergantungan layanan luar.
- Menegakkan **batas otorisasi** secara teknis: trafik "live" ditolak jika host
  target tidak ada di Scope (lihat [011 — Scope Gate](011_scope-gate.md)).
- Menyediakan **mode Simulation** untuk latihan aman memakai data contoh.

## Kategori Hackathon

Kartika Cyber Hackathon 2026 — **Kategori 01: Penindakan** (Offensive Tech).
Produk versi `1.0.0`.

## Kelompok fitur

| Kelompok | Kode | Status | Isi |
|---|---|---|---|
| Fondasi keamanan | 01x | Campur | Scope gate, Root CA & sertifikat, hardening Electron |
| Web Security Suite | 02x | ✅ Nyata | Proxy MITM, Repeater, Intruder, Target, Decoder, Comparer, Sequencer |
| Operations | 03x | ⚪ Simulasi | Dashboard, Scanner, Vulnerabilities, Threat Monitor, Firewall, Reports |

**Catatan penting (koreksi README).** README baris ~67–68 menyebut Proxy, Repeater,
Intruder, dan Target sebagai *canned demo data*. Pembacaan kode menunjukkan
sebaliknya: keempatnya memakai jembatan nyata `window.ruy` ke proses main
(`src/preload/index.ts`, dipakai di `src/renderer/src/pages/web/Proxy.tsx`,
`Repeater.tsx`, `Intruder.tsx`, `Target.tsx`) dan mengirim trafik HTTP(S) sungguhan
lewat `src/main/http.ts` / `src/main/proxy.ts`. Jadi Web Security Suite **nyata**,
bukan demo.

## Tech stack

| Lapisan | Teknologi |
|---|---|
| Runtime desktop | Electron `^33.0.0` |
| UI | React `^18.3.1` + React Router `^6.26.2` (HashRouter) |
| Bahasa | TypeScript `^5.6.2` |
| Bundler / dev | Vite `^5.4.8` via electron-vite `^2.3.0` |
| TLS MITM / sertifikat | node-forge `^1.3.1` |
| Packaging | electron-builder `^25.1.8` (NSIS installer + portable, Windows x64) |
| Ikon build | @resvg/resvg-js, png-to-ico (lihat `scripts/generate-icons.mjs`) |

Tidak ada database atau server: semua state renderer disimpan di `localStorage`
(namespace `ruy.v1.`, lihat `src/renderer/src/store/store.ts`).
