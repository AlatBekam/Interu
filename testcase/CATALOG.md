# Katalog Use Case & Test Case

Status: ✅ otomatis (jalan di `npm test`) · 🖐 manual · ⏳ menunggu (alasan di kolom catatan).

## Use case

| UC | Use case | Dokumen |
| --- | --- | --- |
| UC-01 | Operasi dijaga RoE: hanya teknik/waktu yang diizinkan | [051](../docs/051_roe-audit-log.md) |
| UC-02 | Audit log berantai: setiap keputusan tercatat, manipulasi terdeteksi | [051](../docs/051_roe-audit-log.md) |
| UC-03 | Paket bukti: simpan, ekspor, verifikasi | [052](../docs/052_paket-bukti.md) |
| UC-04 | Probe aktif Rule Engine menghasilkan temuan Confirmed + bukti mentah | [041](../docs/041_rule-engine.md) |
| UC-05 | Retest temuan setelah perbaikan | [053](../docs/053_retest.md) |
| UC-06 | Proxy menegakkan RoE untuk host in-scope | [051](../docs/051_roe-audit-log.md) |
| UC-07 | Attack Path menampilkan jalur ke temuan terparah | [054](../docs/054_attack-path.md) |
| UC-08 | Scope gate (host, IP, CIDR) | [011](../docs/011_scope-gate.md) |
| UC-09 | Deteksi pasif Rule Engine (header, cookie) | [041](../docs/041_rule-engine.md) |

## Test otomatis — integration (`testcase/integration/`)

| TC | Yang diuji | File | Status |
| --- | --- | --- | --- |
| TC-01-01 | Tanpa RoE semua teknik ditolak dan tercatat di `_no-operation` | `roe-gate.test.ts` | ✅ |
| TC-01-02 | Teknik diizinkan lolos, teknik mati ditolak; urutan audit benar | `roe-gate.test.ts` | ✅ |
| TC-01-03 | Di luar jendela waktu ditolak | `roe-gate.test.ts` | ✅ |
| TC-01-04 | Penolakan scope tercatat walau RoE longgar | `roe-gate.test.ts` | ✅ |
| TC-01-05 | RoE tidak valid ditolak; RoE valid bertahan setelah restart | `roe-gate.test.ts` | ✅ |
| TC-02-01 | Rantai 4 entri di disk lolos verifikasi | `audit-log.test.ts` | ✅ |
| TC-02-02 | Baris diubah → rusak di baris itu | `audit-log.test.ts` | ✅ |
| TC-02-03 | Baris tengah dihapus → terdeteksi | `audit-log.test.ts` | ✅ |
| TC-02-04 | Rantai berlanjut benar setelah restart | `audit-log.test.ts` | ✅ |
| TC-02-05 | Operasi bernama `NUL` tetap menulis file nyata (`_NUL.jsonl`) | `audit-log.test.ts` | ✅ |
| TC-02-06 | Target sangat panjang dipotong 500 karakter | `audit-log.test.ts` | ✅ |
| TC-02-07 | KNOWN LIMIT: memotong baris terakhir tidak terdeteksi | `audit-log.test.ts` | ✅ (batasan) |
| TC-03-01 | Paket utuh lolos verifikasi, fingerprint tercatat di log | `evidence.test.ts` | ✅ |
| TC-03-02 | Satu karakter file bukti diubah → gagal | `evidence.test.ts` | ✅ |
| TC-03-03 | File **dan** hash manifest diubah → tetap gagal (`evidence:save`) | `evidence.test.ts` | ✅ |
| TC-03-04 | File tambahan di luar manifest dilaporkan | `evidence.test.ts` | ✅ |
| TC-03-05 | Entri manifest yang keluar dari folder paket ditolak | `evidence.test.ts` | ✅ |
| TC-03-06 | `audit.jsonl` di dalam paket diubah → gagal | `evidence.test.ts` | ✅ |
| TC-03-07 | Ekspor ditolak bila audit log live rusak | `evidence.test.ts` | ✅ |
| TC-03-08 | Nama file bukti selalu dari hash, bukan dari key temuan | `evidence.test.ts` | ✅ |
| TC-03-09 | Dialog dibatalkan → `cancelled` | `evidence.test.ts` | ✅ |

## Test otomatis — unit (`src/shared/*.test.ts`)

| File | UC | Cakupan |
| --- | --- | --- |
| `roe.test.ts` | UC-01 | `roeAllows` (waktu, teknik), `sanitizeRoe` |
| `audit.test.ts` | UC-02 | `chainEntry`, `verifyChain`, `verifyLog` |
| `evidence.test.ts` | UC-03 | `buildManifest`, `verifyManifest`, `isSafeRelPath` |
| `rules.test.ts` | UC-04, UC-09 | `raw`/`req` di temuan, aturan cookie, target per origin |
| `retest.test.ts` | UC-05 | `retestPlan`, `retestStatus`, `appendRetest`, `explicitPorts` |
| `attackPath.test.ts` | UC-07 | `buildAttackGraph`, `tacticOf`, jalur kritis |
| `scope.test.ts` | UC-08 | `expandTargets`, `ipInScope`, `hostInScope` |

## Uji manual (aplikasi berjalan, `npm run dev`)

Target: server lokal yang memang Anda kendalikan, mis. `python -m http.server 8000` di folder berisi `.env` dummy.

| TC | Langkah | Hasil yang diharapkan | Status |
| --- | --- | --- | --- |
| TC-01-M1 | Repeater ke target tanpa RoE | Ditolak "Belum ada Rules of Engagement aktif" | 🖐 |
| TC-01-M2 | RoE dengan Intruder mati → Intruder & Repeater | Intruder ditolak, Repeater berhasil, keduanya di audit log | 🖐 |
| TC-01-M3 | Jendela waktu RoE di masa lalu → scan / proxy | Ditolak "Di luar jendela waktu" | 🖐 |
| TC-04-M1 | Rule Engine → Run active checks | `expose-dotenv` Confirmed; file bukti muncul di userData | 🖐 |
| TC-03-M1 | Export evidence → Verify package; lalu ubah file / manifest | ✅ lalu ❌ dengan nama file | 🖐 |
| TC-02-M1 | Ubah satu baris file audit → Verify integrity | ❌ di baris itu | 🖐 |
| TC-05-M1 | Hapus `.env` → Retest all | `closed`, riwayat bertambah | 🖐 |
| TC-05-M2 | Matikan server → Retest all | `error`, bukan `closed` | 🖐 |
| TC-06-M1 | Proxy + browser bawaan ke target in-scope, RoE `proxy` mati | 403 "Blocked by Interu RoE" | 🖐 |
| TC-07-M1 | Buka Attack Path setelah ada temuan | Host → service → temuan, jalur kritis merah | 🖐 |

## Menunggu

| Item | Catatan |
| --- | --- |
| UC-04 / UC-05 / UC-06 otomatis | Butuh trafik ke server uji; diputuskan uji manual dulu. `helpers/target-server.ts` sudah siap. |
| Handler IPC `src/main/index.ts` | Handler terdaftar di dalam blok Electron sehingga tidak bisa diimpor; menunggu refactor `ipc/*.ts`. |
| Alur retest `Vulnerabilities.tsx` (`retestOne`) | Ada di komponen React; menunggu dipindah ke use case / service. |
| E2E di window Electron | Menunggu install script Electron disetujui (`npm approve-scripts electron`) + keputusan alat (mis. Playwright). |
