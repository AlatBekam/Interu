# 034 — Exposure Monitor (dulu Threat Monitor)

← [033 — Vulnerability Assessment](033_vulnerabilities.md) · [Index](000_index.md) · [037 — Settings](037_settings.md) →

## Status

✅ **NYATA** — Halaman ini hanya menampilkan apa yang diamati Interu sendiri: temuan, scan, keputusan scope, dan request yang ditahan proxy. Generator event palsu sudah dihapus. Halaman ini **bukan sistem deteksi intrusi** dan tidak memantau komputer atau jaringanmu dari serangan.

## Tujuan fitur

Menjawab "apa yang perlu ditindak lebih dulu dari hasil kerja saya?": antrian prioritas (KEV dahulu, lalu severity), eksposur per host, dan linimasa aktivitas sesi ini.

## Cara kerja

Sumber data (semua sudah ada di aplikasi):

| Sumber | Event yang dicatat |
| --- | --- |
| Store temuan (`store/findings.ts`) | `New finding: <nama>` saat temuan baru masuk; `Resolved: <nama>` saat dihapus setelah re-test |
| Network Scanner (`startLive`) | `Scan started: <target> (<profil>)`, `Scan finished: <n> host(s) up, <n> open port(s)` |
| Penolakan scope (`inScopeOrNote`, `sendLive`) | `Blocked by scope: <target> (<fitur>)` |
| Proxy intercept (`onIntercept`) | `Request held: <metode> <host>` |

Logika murni ada di `src/shared/activity.ts` (antrian prioritas, eksposur per host, ringkasan, format waktu). Store `store/activity.ts` menyimpan maksimal **200** event terbaru di memori saja; restart aplikasi mengosongkannya.

Level event: `critical`/`high` → crit, `medium` → warn, `low`/`info` → info. Temuan ber-KEV selalu crit, dan temuan yang sudah resolved bernilai ok.

Halaman ini adalah **landing page** aplikasi: route `/` mengarahkan (`Navigate`) ke `/threats`.

## Batasan / temuan

- Bukan IDS. Tidak melihat serangan terhadap komputer atau jaringanmu. Telemetri host (Windows Event Log, log firewall, IDS seperti Suricata) **tidak termasuk** dan merupakan fitur terpisah.
- Aktivitas hilang saat aplikasi ditutup. Ini disengaja: tidak ada yang disimpan.
- Temuan produk KEV (dari fingerprint banner/header) tidak dihitung sebagai "actively exploited"; lihat [041](041_rule-engine.md).
- Dashboard, Firewall Rules, dan Reports sudah dihapus; tidak ada lagi halaman yang memakai data mock.

## File terkait

| File | Fungsi |
| --- | --- |
| [../src/shared/activity.ts](../src/shared/activity.ts) | Logika murni: `eventFromFinding`, `priorityQueue`, `exposureByTarget`, `summarize`, `timeLabel` |
| [../src/renderer/src/store/activity.ts](../src/renderer/src/store/activity.ts) | Store aktivitas dalam memori (200 event): `pushActivity`, `noteScopeBlock`, `useActivity` |
| [../src/renderer/src/pages/ThreatMonitor.tsx](../src/renderer/src/pages/ThreatMonitor.tsx) | Halaman "Exposure Monitor" (route `/threats`) |
| [../src/renderer/src/lib/http.ts](../src/renderer/src/lib/http.ts) | `inScopeOrNote` dan pencatatan penolakan di `sendLive` |
| [../testcase/e2e/monitor.e2e.ts](../testcase/e2e/monitor.e2e.ts) | GUI e2e: kosong di awal, temuan nyata, tanpa halaman palsu, penolakan scope |

## Cara pakai

1. Buka **Exposure Monitor** (sidebar grup Operations). Halaman kosong sampai ada temuan atau aktivitas.
2. Jalankan scan (Network Scanner) atau active checks (Rule Engine) terhadap target yang ada di scope. Antrian dan eksposur akan terisi.
3. **Clear** di panel Activity menghapus linimasa. Temuan tidak ikut terhapus.

## Checklist pengerjaan

- [x] Logika murni aktivitas dengan tes (`activity.test.ts`).
- [x] Store dalam memori dengan batas 200 event.
- [x] Sumber nyata: temuan, scan, scope, proxy intercept.
- [x] Generator palsu dan setting `liveFeed` dihapus.
- [x] Halaman palsu (Dashboard) dihapus; Exposure Monitor menjadi landing page.
- [x] GUI e2e (`monitor.e2e.ts`).
- [ ] Sensor host (Windows Event Log / IDS): di luar cakupan.

