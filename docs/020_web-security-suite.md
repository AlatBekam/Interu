# 020 — Web Security Suite (Pengantar)

← [013 — Hardening Electron](013_hardening-electron.md) · [Index](000_index.md) · [021 — Proxy / MITM](021_proxy-mitm.md) →

> Kelompok fitur bergaya **Burp Suite** di dalam Interu ("Interu — Cyber Operations", brand lama **RUY**). Berisi tujuh modul: Target, Proxy, Repeater, Intruder, Sequencer, Decoder, Comparer. Semua berada di `src/renderer/src/pages/web/` dengan backend di proses `main` (`src/main/proxy.ts`, `src/main/http.ts`, `src/main/index.ts`).

## Tujuan

Menyediakan alat pentest web interaktif di dalam satu aplikasi desktop Electron, dengan dua prinsip utama:

1. **Legal-by-design** — semua request *live* melewati **gerbang scope** (`hostInScope`, [`../src/shared/http.ts`](../src/shared/http.ts)). Scope kosong = tidak ada target yang diizinkan.
2. **Sim vs Live** — tiap modul yang berpotensi mengirim trafik punya mode **Simulation** (data buatan, tidak ada paket keluar) dan **Live** (request nyata lewat proses main).

## Daftar fitur

| # | Modul | Dokumen | Route | Status |
|---|-------|---------|-------|--------|
| 021 | Proxy / MITM | [021_proxy-mitm.md](021_proxy-mitm.md) | `/web/proxy` | ✅ NYATA |
| 022 | Repeater | [022_repeater.md](022_repeater.md) | `/web/repeater` | 🟡 SEBAGIAN |
| 023 | Intruder | [023_intruder.md](023_intruder.md) | `/web/intruder` | 🟡 SEBAGIAN |
| 024 | Target / Discovery | [024_target-discovery.md](024_target-discovery.md) | `/web/target` | 🟡 SEBAGIAN |
| 025 | Decoder | [025_decoder.md](025_decoder.md) | `/web/decoder` | ✅ NYATA |
| 026 | Comparer | [026_comparer.md](026_comparer.md) | `/web/comparer` | ✅ NYATA |
| 027 | Sequencer | [027_sequencer.md](027_sequencer.md) | `/web/sequencer` | 🟡 SEBAGIAN |

Rute terdaftar di [`../src/renderer/src/App.tsx`](../src/renderer/src/App.tsx); menu di [`../src/renderer/src/components/Sidebar.tsx`](../src/renderer/src/components/Sidebar.tsx) grup "Web Security Suite".

## Alur antar modul

Proxy (dan Target) bisa mengoper request ke Repeater/Intruder lewat **transfer bus** satu-tembak ([`../src/renderer/src/store/transfer.ts`](../src/renderer/src/store/transfer.ts)). Menu klik-kanan juga menyediakan **Copy as curl** (`toCurl`, [`../src/renderer/src/lib/http.ts`](../src/renderer/src/lib/http.ts)). Semua request Live melewati **gerbang scope**.

```mermaid
flowchart TD
  subgraph Renderer
    PX["Proxy (/web/proxy)"]
    TG["Target (/web/target)"]
    RP["Repeater (/web/repeater)"]
    IN["Intruder (/web/intruder)"]
    BUS["transfer bus (setTransfer / takeTransfer)"]
    CURL["Copy as curl (toCurl)"]
    GATE{"hostInScope? (scope gate)"}
  end
  subgraph Main
    HTTP["ruy:http -> sendHttp"]
    PROXY["startProxy MITM"]
  end
  PX -->|"Send to Repeater/Intruder"| BUS
  TG -->|"Send to Repeater/Intruder"| BUS
  BUS -->|"useTransfer (sekali)"| RP
  BUS -->|"useTransfer (sekali)"| IN
  PX -.->|"klik kanan"| CURL
  TG -.->|"klik kanan"| CURL
  RP -->|"Live"| GATE
  IN -->|"Live"| GATE
  TG -->|"Live"| GATE
  GATE -->|"lolos"| HTTP
  GATE -->|"tolak"| BLK["blocked: true"]
  PX -->|"start/stop"| PROXY
  PROXY -->|"ruy:proxy:log / intercept"| PX
```

> **Catatan penting:** gerbang scope berlaku untuk jalur `ruy:http` (Repeater/Intruder/Target Live). Jalur **Proxy MITM** (`handleRequest`) **tidak** di-scope-gate — lihat [021 §6](021_proxy-mitm.md#6-batasan--temuan).

## Status: Live vs Sim

| Modul | Mode tersedia | Yang benar-benar terjadi |
|-------|---------------|--------------------------|
| Proxy | Live + sample offline | MITM proxy nyata; "Load sample"/"Demo" = data offline |
| Target | Sim + Live | Sim: `SITE_MAP` buatan. Live: discovery wordlist nyata |
| Repeater | Sim + Live | Sim: respon canned. Live: `sendHttp` nyata |
| Intruder | Sim + Live | Sim: baris difabrikasi. Live: request per payload nyata |
| Sequencer | Sim only | Token dibuat lokal (`sampleTokens`); matematika entropi nyata |
| Decoder | Offline nyata | Transform URL/Base64/Hex/HTML/ASCII beneran |
| Comparer | Offline nyata | LCS line-diff beneran |

## Urutan pengerjaan (disarankan)

1. Baca pengantar ini (020).
2. **021 Proxy** — fondasi penangkapan trafik + MITM.
3. **022 Repeater** & **023 Intruder** — konsumen transfer bus.
4. **024 Target** — site map + content discovery.
5. **025 Decoder**, **026 Comparer**, **027 Sequencer** — utilitas pendukung.
6. Lanjut ke [030 Operations](030_operations.md).

## File terkait (ringkas)

| File | Peran |
|------|-------|
| [`../src/main/proxy.ts`](../src/main/proxy.ts) | Mesin proxy intercept + MITM TLS |
| [`../src/main/http.ts`](../src/main/http.ts) | Klien HTTP(S) nyata (`sendHttp`) |
| [`../src/main/index.ts`](../src/main/index.ts) | Handler IPC `ruy:*` + scope gate |
| [`../src/preload/index.ts`](../src/preload/index.ts) | Bridge `window.ruy` |
| [`../src/shared/http.ts`](../src/shared/http.ts) | `hostInScope`, tipe `HttpReq`/`HttpRes` |
| [`../src/shared/proxy.ts`](../src/shared/proxy.ts) | Tipe `ProxyLogEntry`, `HeldRequest` |
| [`../src/renderer/src/lib/http.ts`](../src/renderer/src/lib/http.ts) | `parseRawRequest`, `toCurl`, `sendLive` |
| [`../src/renderer/src/store/transfer.ts`](../src/renderer/src/store/transfer.ts) | Transfer bus Send-to-Repeater/Intruder |
| [`../src/renderer/src/data/burp.ts`](../src/renderer/src/data/burp.ts) | Data simulasi (history, payloads, token) |

---
← [013 Hardening Electron](013_hardening-electron.md) · [Index](000_index.md) · [next: 021 Proxy / MITM](021_proxy-mitm.md) →
