# 002 — Setup & Build

← [001 — Ringkasan Proyek](001_ringkasan-proyek.md) · [Index](000_index.md) · [003 — Arsitektur](003_arsitektur.md) →

## Prasyarat

- **Node.js** (disarankan v20+) dan **npm** (Node 22 types dipakai di devDeps).
- **Windows x64** untuk menghasilkan installer (target build hanya Windows).
- Koneksi internet untuk `npm install` saja; aplikasi berjalan sepenuhnya offline.

## Instalasi

```bash
npm install
```

## Scripts (dari `package.json`)

| Script | Perintah | Fungsi |
|---|---|---|
| `dev` | `electron-vite dev` | Jalankan app mode development dengan HMR (dev server renderer). |
| `start` | `electron-vite preview` | Preview hasil build produksi tanpa dev server. |
| `build` | `electron-vite build` | Compile main + preload + renderer ke `out/`. |
| `typecheck:node` | `tsc --noEmit -p tsconfig.node.json --composite false` | Type-check kode main/preload/shared. |
| `typecheck:web` | `tsc --noEmit -p tsconfig.web.json --composite false` | Type-check kode renderer. |
| `typecheck` | `npm run typecheck:node && npm run typecheck:web` | Jalankan kedua type-check di atas. |
| `icons` | `node scripts/generate-icons.mjs` | Generate `build/icon.ico` & `icon.png` dari SVG. |
| `smoke` | `cross-env RUY_SMOKE_TEST=1 electron .` | Jalankan bundle produksi sekali, cetak `RUY_SMOKE_RESULT: RENDER_OK`, lalu keluar. Verifikasi bundle benar-benar termuat. |
| `dist` | `npm run build && electron-builder --win --x64` | Build + buat installer NSIS dan portable `.exe`. |
| `dist:dir` | `npm run build && electron-builder --win --dir` | Build + keluaran folder unpacked (tanpa installer), untuk uji cepat. |

> `smoke` butuh `out/` sudah ada (jalankan `build` dulu), karena `electron .`
> memuat `main: out/main/index.js`.

## Environment variable `RUY_*`

Semua dibaca di `src/main/index.ts`. Hanya untuk dev / verifikasi build; tidak ada
efek pada penggunaan normal.

| Variabel | Nilai | Efek |
|---|---|---|
| `RUY_SMOKE_TEST` | `1` | Window tidak ditampilkan; setelah renderer selesai load, cetak `RUY_SMOKE_RESULT: RENDER_OK` dan `app.quit()` setelah ~1,5 dtk. |
| `RUY_START_ROUTE` | mis. `/web/proxy` | Buka route tertentu langsung lewat hash saat start. |
| `ELECTRON_RENDERER_URL` | URL dev server | Disetel electron-vite saat `dev`; menentukan apakah renderer dimuat dari URL dev atau file bundle. |
| `RUY_HTTP_TEST` | URL | Kirim satu GET nyata lewat `sendHttp`, cetak `RUY_HTTP_RESULT: ...`, lalu keluar. |
| `RUY_PROXY_TEST` | apa saja (truthy) | Start proxy di port `18080`, kirim satu request http + satu https (CONNECT+MITM) lewat proxy, cetak `RUY_PROXY_*` log, lalu keluar. |

## Output build (`electron-builder.yml`)

- `appId`: `com.interu.cyberops`, `productName`: `Interu`.
- `directories.output`: **`release/`**, `buildResources`: `build/`.
- Yang dibundel: `out/**/*` + `package.json` (source di-strip).
- Target Windows x64:
  - **NSIS installer** → `Interu-Setup-1.0.0.exe` (bukan one-click; boleh pilih
    folder instalasi; bikin shortcut desktop + start menu).
  - **Portable** → `Interu-Portable-1.0.0.exe`.
- `forceCodeSigning: false` — build **tidak** di-sign, jadi SmartScreen/antivirus
  bisa memperingatkan (wajar untuk tool proxy/MITM); pilih "Run anyway" / whitelist.

## Interu Root CA — import & hapus

Untuk menangkap **HTTPS di browser eksternal**, root CA Interu harus dipercaya OS/
browser. (Browser bawaan "Open Browser" sudah auto-trust — lihat
[012](012_root-ca-dan-sertifikat.md).)

### Export CA

Dari halaman **Proxy**, tekan **Export CA**. File ditulis ke folder **Downloads**
sebagai `Interu-Root-CA.crt` (handler `ruy:proxy:exportCA` → `exportCA(app.getPath('downloads'))`
di `src/main/index.ts`).

### Import ke Windows (OS trust store)

1. Klik dua kali `Interu-Root-CA.crt` → **Install Certificate**.
2. Pilih **Local Machine** (atau Current User) → **Place all certificates in the
   following store** → **Trusted Root Certification Authorities**.
3. Selesai → Finish.

### Import ke Firefox (trust store sendiri)

Settings → Privacy & Security → Certificates → **View Certificates** → **Import** →
pilih file → centang "Trust this CA to identify websites".

### Menghapus / mencabut CA

- **Windows:** jalankan `certmgr.msc` → Trusted Root Certification Authorities →
  Certificates → hapus **Interu Root CA**.
- **Firefox:** Certificate Manager → Authorities → pilih Interu Root CA → **Delete
  or Distrust**.

> **Peringatan.** Private key CA disimpan tanpa enkripsi di
> `userData/ca/interu-ca.key` dan aplikasi **tidak** punya mekanisme revoke/cleanup
> otomatis. Setelah selesai dipakai, hapus trust CA dari OS/browser secara manual
> (dan boleh hapus folder `ca/` di userData). Detail: [012](012_root-ca-dan-sertifikat.md).
