# 053 — Retest (Verifikasi Perbaikan)

← [052 — Paket Bukti](052_paket-bukti.md) · [Index](000_index.md) · [054 — Attack Path](054_attack-path.md) →

## Status

✅ **NYATA** — Tombol **Retest all** di Vulnerabilities (Live) memutar ulang pengecekan di balik setiap temuan, lewat RoE teknik `retest`. Logika status diuji di `retest.test.ts`.

## Tujuan fitur

Setelah sistem diperbaiki, operator perlu bukti bahwa perbaikannya berhasil, tanpa mengulang seluruh operasi secara manual.

## Cara kerja

| Sumber temuan | Cara retest | Teknik RoE |
| --- | --- | --- |
| `active` (punya `req`) | Kirim ulang `finding.req` yang sama lewat `ruy:http`, lalu `matchActive` dengan template yang sama | `retest` |
| `scanner` (punya port) | `ruy:scan:tcp` dengan `ports: [port]`, `retest: true`, lalu `analyzeScan` dan cocokkan key | `retest` |
| `proxy` (pasif) | Tidak otomatis → kolom Retest menampilkan **manual** (jelajahi ulang lewat Proxy) | — |

Status (`retestStatus`):

| Status | Arti |
| --- | --- |
| `closed` | Pengecekan tidak lagi cocok → perbaikan berhasil |
| `open` | Masih cocok dengan bukti yang sama |
| `changed` | Masih cocok, tetapi buktinya berbeda |
| `error` | Tidak ada respons (host mati, timeout, diblokir); **bukan** bukti perbaikan |

- Hasil **ditambahkan** ke `finding.retests[]` (`{ at, status, note? }`) lewat `recordRetest`. `evidence` dan `raw` asli tidak disentuh.
- `addFindings` mempertahankan riwayat retest saat temuan yang sama muncul lagi.
- Setiap retest menulis snapshot bukti baru dan entri audit (request-nya melewati `authorize('retest', ...)`).
- Retest berhenti di temuan pertama yang diblokir scope/RoE.

## File terkait

| File | Fungsi |
| --- | --- |
| [../src/shared/retest.ts](../src/shared/retest.ts) | `retestPlan`, `retestStatus`, `appendRetest`, `latestRetest` |
| [../src/shared/rules.ts](../src/shared/rules.ts) | `RetestStatus`, `RetestRecord`, `Finding.retests` |
| [../src/shared/scan.ts](../src/shared/scan.ts) | `ScanRequest.ports` / `retest`, `explicitPorts` (validasi 1–64 port) |
| [../src/main/index.ts](../src/main/index.ts) | `ruy:scan:tcp` memakai port eksplisit dan teknik `retest` |
| [../src/renderer/src/store/findings.ts](../src/renderer/src/store/findings.ts) | `recordRetest`, pelestarian riwayat di `addFindings` |
| [../src/renderer/src/pages/Vulnerabilities.tsx](../src/renderer/src/pages/Vulnerabilities.tsx) | `retestOne`, tombol **Retest all**, kolom **Retest** |
| [../src/shared/retest.test.ts](../src/shared/retest.test.ts) | Tes rencana, status, riwayat, validasi port |

## Cara pakai

1. Pastikan RoE mengizinkan teknik **retest**.
2. Buka **Vulnerabilities** → tampilan **Live** → **Retest all**.
3. Ringkasan muncul di atas tabel (closed / open / changed / error / manual). Arahkan kursor ke status untuk melihat jumlah retest dan catatan terakhir.

## Batasan / temuan

- Retest berjalan berurutan untuk semua temuan; belum bisa memilih temuan tertentu.
- Temuan pasif proxy tidak bisa diuji otomatis.
- Temuan banner (profil `deep`) di-retest dengan profil `quick` tanpa banner grab, jadi bisa tampil `closed` walau versi belum diperbarui.
- Riwayat retest tersimpan di localStorage renderer bersama temuan; salinan permanennya ada di snapshot bukti di disk.

## Checklist pengerjaan

- [x] Model status + riwayat tanpa menimpa bukti (teruji).
- [x] Retest HTTP aktif dan port tunggal, keduanya lewat RoE.
- [x] UI Retest all + kolom status.
- [ ] Retest per temuan / per host.
- [ ] Banner grab saat retest temuan banner.
- [ ] Bagian "Verifikasi Perbaikan" di Reports.
