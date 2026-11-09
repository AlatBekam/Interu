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
| `test` | `vitest run` | Unit test kode `src/shared/` (lihat di bawah). |

> `smoke` butuh `out/` sudah ada (jalankan `build` dulu), karena `electron .`
> memuat `main: out/main/index.js`.

> **VS Code terminal.** Terminal VS Code bisa mewariskan `ELECTRON_RUN_AS_NODE=1`;
> dengan itu `electron .` jalan sebagai Node biasa (tanpa window). Unset dulu
> sebelum `smoke` / hook `RUY_*`: PowerShell `Remove-Item Env:ELECTRON_RUN_AS_NODE`,
> bash `unset ELECTRON_RUN_AS_NODE`.

## Test (`npm test`)

`vitest run` menjalankan semua `*.test.ts` (21 file, 262 test, 3 di-skip) tanpa Electron dan tanpa jaringan. Jumlah di atas berubah seiring fitur; jalankan `npm test` untuk angka terkini.

| Area | File | Isi |
|---|---|---|
| Scope & jaringan | `src/shared/scope.test.ts` | `expandTargets`, `ipInScope`, `hostInScope` (CIDR, mask kosong, hostname vs IP) |
| Rule Engine | `rules.test.ts`, `dsl.test.ts`, `advice.test.ts`, `cve-tags.test.ts`, `fingerprint.test.ts`, `product-findings.test.ts` | matcher, extractor, DSL, korelasi, baseline soft-404, integritas katalog 408 template, saran Attack/Defense, tag CVE, deteksi produk |
| KEV | `kev.test.ts`, `kev-badge.test.ts`, `cve-cell.test.ts` | pencarian KEV, label badge, teks sel CVE |
| Exposure Monitor | `activity.test.ts`, `activity-product.test.ts` | antrean prioritas, eksposur per host, ringkasan |
| Crawler & Active Scan | `crawl.test.ts`, `webvuln.test.ts` | BFS crawler, ekstraksi link/form, oracle SQLi/XSS/IDOR/CSRF |
| Sequencer | `tokens.test.ts` | `parseTokens`, `analyzeTokens` |
| Browser terproksi | `browser.test.ts` | `normalizeAddress`, `isNavigableUrl` |
| Scan terautentikasi | `auth.test.ts` | `parseAuthHeaders`, `mergeAuth`, `isUnsafeAuthedPath`, `lostSession`, `redactSecrets` |
| Tampilan | `src/renderer/src/styles/tokens.test.ts`, `consistency.test.ts` | kontras token (WCAG AA), larangan gradient/glow/warna hard-coded/emoji |

### Tes e2e (aplikasi nyata)

Butuh build produksi dan **tidak boleh ada jendela Interu lain yang terbuka** (kunci single-instance). Semuanya memakai server lokal di `127.0.0.1` dan userData sementara.

```bash
npm run build
npx vitest run --config testcase/e2e/vitest.config.ts            # semua
npx vitest run --config testcase/e2e/vitest.config.ts testcase/e2e/browser.e2e.ts   # satu file
```

| Spec | Yang diuji |
|---|---|
| `gui.e2e.ts` | Repeater live, gerbang scope, kirim setelah scope diisi |
| `rules-408.e2e.ts` | Katalog 408 template tampil; hanya tiga penanda yang disajikan server lokal yang terkonfirmasi; tag CVE dan badge KEV; saran Defense/Attack; server catch-all tidak menghasilkan temuan; Clear menghapus semua |
| `fingerprint.e2e.ts` | Deep scan: temuan produk KEV tidak dihitung sebagai "actively exploited" |
| `monitor.e2e.ts` | Exposure Monitor hanya menampilkan aktivitas nyata; tidak ada halaman palsu |
| `browser.e2e.ts` | Address bar, back/forward, skema terlarang, `target=_blank`, trafik tercatat di HTTP History |
| `auth-scan.e2e.ts` | Scan terautentikasi: cookie browser, header manual, lewati logout, sesi habis + Refresh |
| `ui-audit.e2e.ts` | Setiap halaman di tema gelap dan terang: tanpa error dan tanpa overflow; menyimpan tangkapan layar |
| `webgoat.e2e.ts` | **Opsional**, hanya jalan bila `WEBGOAT_URL`, `WEBGOAT_USER`, `WEBGOAT_PASS` diisi; menguji scan terautentikasi ke WebGoat milik sendiri |

Port 8080 sering dipakai proses lain (mis. relay WSL), jadi spec yang menyalakan proxy memakai port sendiri lewat kolom port di halaman Proxy.

## Environment variable `RUY_*`

Semua dibaca di `src/main/index.ts`. Hanya untuk dev / verifikasi build; tidak ada
efek pada penggunaan normal.

| Variabel | Nilai | Efek |
|---|---|---|
| `RUY_SMOKE_TEST` | `1` | Window tidak ditampilkan; setelah renderer selesai load, cetak `RUY_SMOKE_RESULT: RENDER_OK` dan `app.quit()` setelah ~1,5 dtk. |
| `RUY_START_ROUTE` | mis. `/web/proxy` | Buka route tertentu langsung lewat hash saat start. |
| `ELECTRON_RENDERER_URL` | URL dev server | Disetel electron-vite saat `dev`; menentukan apakah renderer dimuat dari URL dev atau file bundle. |
| `RUY_HTTP_TEST` | URL | Kirim satu GET nyata lewat `sendHttp`, cetak `RUY_HTTP_RESULT: ...`, lalu keluar. |
| `RUY_PROXY_TEST` | apa saja (truthy) | Start proxy di port `18080`, kirim satu request http + satu https (CONNECT) ke `example.com` lewat proxy, cetak `RUY_PROXY_*` / `RUY_MITM_*`, lalu keluar. |
| `RUY_PROXY_SCOPE` | daftar dipisah koma, mis. `example.com` | Scope proxy untuk `RUY_PROXY_TEST` (via `setScope`). Kosong = uji jalur out-of-scope: request diteruskan apa adanya, CONNECT jadi tunnel buta, **tidak ada** baris `RUY_PROXY_LOG`. Isi `example.com` untuk menguji jalur MITM + log. |

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
