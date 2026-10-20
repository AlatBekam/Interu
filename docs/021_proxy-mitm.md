# 021 — Proxy / MITM

← [020 — Web Security Suite (Pengantar)](020_web-security-suite.md) · [Index](000_index.md) · [022 — Repeater](022_repeater.md) →

## 1. Status

✅ **NYATA** — proxy forward intercept sungguhan dengan MITM HTTPS. Ada juga data sample/demo offline sebagai pelengkap.

## 2. Tujuan fitur

Menangkap seluruh trafik HTTP dan (via MITM) HTTPS yang melewati proxy, menampilkannya di **HTTP History**, serta memungkinkan operator **menahan (hold), meneruskan (forward), menjatuhkan (drop), atau mengedit** request sebelum diteruskan ke server.

## 3. Cara kerja

**Backend ([`../src/main/proxy.ts`](../src/main/proxy.ts)):**
- `startProxy(port, emitFn)` membuat dua server: `http.createServer()` (listen `127.0.0.1:port`) dan `https.createServer()` MITM dengan `SNICallback` yang mencetak sertifikat per-host dari root CA Interu (`getHostCert`, [`../src/main/ca.ts`](../src/main/ca.ts)).
- Event `connect` (CONNECT dari klien untuk HTTPS) membalas `200 Connection Established` lalu menyerahkan socket mentah ke server MITM (`mitm.emit('connection', clientSocket)`) — bukan tunnel buta, sehingga TLS diterminasi lokal dan isinya terlihat.
- `handleRequest` menyusun raw request (`buildRawReq`), dan bila `intercepting` menyala, meng-emit `ruy:proxy:intercept` lalu menunggu keputusan di `pending` Map. Setelah forward, request diteruskan dengan `http`/`https.request` (`rejectUnauthorized: false`) dan hasilnya di-emit sebagai `ruy:proxy:log`.
- `setIntercept`, `resolveIntercept(id, action, raw)`, `stopProxy()`, `getPort()`, `isRunning()`.

**IPC ([`../src/main/index.ts`](../src/main/index.ts)):** `ruy:proxy:start|stop|status|intercept|resolve|openBrowser|exportCA`. Event dikirim ke renderer lewat `emitToRenderer`; khusus `ruy:proxy:intercept`, window utama di-`show()`/`focus()` agar operator bisa menekan Forward/Drop.

**Browser terproksi (`ruy:proxy:openBrowser`):** membuka `BrowserWindow` baru dengan `session.fromPartition('interu-proxied')`, memasang `setProxy({ proxyRules: '127.0.0.1:<port>' })` dan `setCertificateVerifyProc((_req, cb) => cb(0))` (mempercayai sertifikat MITM otomatis). Satu window dipakai ulang (`proxiedBrowser`). `ruy:proxy:exportCA` menulis `Interu-Root-CA.crt` ke folder Downloads untuk browser eksternal.

**Frontend ([`../src/renderer/src/pages/web/Proxy.tsx`](../src/renderer/src/pages/web/Proxy.tsx)):** berlangganan `onLog`/`onIntercept`, tombol Start/Stop, toggle Intercept, Open Browser, Export CA, "Demo (offline)" (render `BrowserSim`), "Load sample" (dari `HTTP_HISTORY`). Klik-kanan baris history → Send to Repeater/Intruder (`setTransfer`, mode `live`), Copy URL, Copy as curl (`toCurl`).

```mermaid
sequenceDiagram
  participant B as "Browser terproksi"
  participant P as "Proxy (main)"
  participant UI as "Proxy.tsx"
  participant S as "Server target"
  B->>P: "CONNECT host:443 / GET http://..."
  P->>UI: "ruy:proxy:intercept (bila Intercept on)"
  UI->>P: "ruy:proxy:resolve (forward / drop / edit raw)"
  P->>S: "request diteruskan"
  S-->>P: "response"
  P-->>B: "response"
  P->>UI: "ruy:proxy:log (request + response)"
```

## 4. File terkait

| File | Fungsi utama |
|------|--------------|
| [`../src/main/proxy.ts`](../src/main/proxy.ts) | `startProxy`, `stopProxy`, `handleRequest`, `setIntercept`, `resolveIntercept`, `parseRaw`, `buildRawReq` |
| [`../src/main/ca.ts`](../src/main/ca.ts) | `getCA`, `getHostCert`, `exportCA` |
| [`../src/main/index.ts`](../src/main/index.ts) | handler IPC `ruy:proxy:*`, `emitToRenderer`, `ruy:proxy:openBrowser` |
| [`../src/preload/index.ts`](../src/preload/index.ts) | `proxy.start/stop/status/setIntercept/resolve/openBrowser/exportCA/onLog/onIntercept` |
| [`../src/shared/proxy.ts`](../src/shared/proxy.ts) | `ProxyLogEntry`, `HeldRequest` |
| [`../src/renderer/src/pages/web/Proxy.tsx`](../src/renderer/src/pages/web/Proxy.tsx) | UI: history, intercept, browser, export CA |
| [`../src/renderer/src/pages/web/BrowserSim.tsx`](../src/renderer/src/pages/web/BrowserSim.tsx) | Browser simulasi offline tertanam (Demo) |

## 5. Cara pakai

1. Buka **Proxy** (`/web/proxy`), set port (default 8080), klik **Start**.
2. Klik **Open Browser** untuk membuka browser terproksi yang otomatis mempercayai CA Interu (http & https tertangkap). Atau arahkan proxy browser eksternal ke `127.0.0.1:8080` dan **Export CA** lalu trust di OS/browser.
3. Nyalakan **Intercept** untuk menahan request; edit raw di textarea bila perlu, lalu **Forward** atau **Drop**.
4. Lihat **HTTP History**; klik baris untuk inspeksi Request/Response; klik-kanan untuk Send to Repeater/Intruder atau Copy as curl.
5. Tanpa target nyata: klik **Load sample** atau **Demo (offline)** untuk data contoh.

## 6. Batasan / temuan

- **Temuan: `handleRequest` tidak di-scope-gate.** Diverifikasi — proxy meneruskan request ke host apa pun yang melewatinya; `hostInScope` hanya dipakai di handler `ruy:http` ([`../src/main/index.ts`](../src/main/index.ts) baris ~123), bukan di `src/main/proxy.ts`. Gerbang scope "legal-by-design" **tidak** melindungi jalur proxy.
- `BrowserSim` (Demo offline) **tidak** didaftarkan sebagai route di `App.tsx`; ia hanya dirender di dalam `Proxy.tsx` saat tombol Demo ditekan. Browser nyata memakai `ruy:proxy:openBrowser` (BrowserWindow terpisah), bukan `BrowserSim`.
- Proxy mendengar hanya di `127.0.0.1`. Body non-teks di history diringkas (`[N bytes ... omitted]`), raw dipotong `CAP = 50000` byte.
- Tipe `ProxyLogEntry.kind` dideklarasikan `'http' | 'https-tunnel'`, tetapi `proxy.ts` meng-emit `kind: scheme` bernilai `'http'`/`'https'` — mismatch tipe minor (tidak mempengaruhi runtime).
- Error upstream dibalas `502`; request yang di-drop dibalas `502 Dropped by Interu`.

## 7. Checklist pengerjaan

- [ ] Verifikasi `startProxy` listen di `127.0.0.1:8080` dan `isRunning()` benar.
- [ ] Uji Open Browser: http dan https tertangkap, sertifikat MITM dipercaya.
- [ ] Uji Intercept: hold → edit raw → Forward meneruskan versi tereedit; Drop balas 502.
- [ ] Uji Export CA menulis `Interu-Root-CA.crt` ke Downloads.
- [ ] Konfirmasi klik-kanan history mengoper ke Repeater/Intruder (mode live) dan Copy as curl benar.
- [ ] **Perbaiki temuan:** tambahkan scope gate (`hostInScope`) pada `handleRequest` sebelum meneruskan request.

---
← [020 Web Security Suite](020_web-security-suite.md) · [Index](000_index.md) · [next: 022 Repeater](022_repeater.md) →
