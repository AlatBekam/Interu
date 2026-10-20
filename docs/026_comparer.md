# 026 — Comparer

← [025 — Decoder](025_decoder.md) · [Index](000_index.md) · [027 — Sequencer](027_sequencer.md) →

## 1. Status

✅ **NYATA** — diff baris LCS (Longest Common Subsequence) sungguhan, **offline**.

## 2. Tujuan fitur

Membandingkan dua teks/respon baris-per-baris untuk menyorot perbedaan — mis. membandingkan respon 200 vs 403 pada kasus kontrol akses (IDOR/BOLA). Sudah dimuati dua respon simulasi (order id 1001 = 200 vs 1002 = 403).

## 3. Cara kerja

`lineDiff(a, b)` ([`../src/renderer/src/pages/web/Comparer.tsx`](../src/renderer/src/pages/web/Comparer.tsx)) membangun tabel DP LCS lalu menelusuri balik untuk menghasilkan operasi `same` / `add` / `del`:

- Tabel `dp[i][j]` diisi dari belakang: `a[i]===b[j] ? dp[i+1][j+1]+1 : max(dp[i+1][j], dp[i][j+1])`.
- Telusur: jika sama → `same`; else pilih `del` (dari A) atau `add` (dari B) berdasarkan nilai dp.
- `diff` dan `stats` (add/del/same) dihitung dengan `useMemo` atas `left.split('\n')` dan `right.split('\n')`.

Input awal: `LEFT = rawResponse(HTTP_HISTORY[5])` (/api/orders?id=1001, 200), `RIGHT = rawResponse(HTTP_HISTORY[6])` (/api/orders?id=1002, 403).

## 4. File terkait

| File | Fungsi utama |
|------|--------------|
| [`../src/renderer/src/pages/web/Comparer.tsx`](../src/renderer/src/pages/web/Comparer.tsx) | `lineDiff`, `stats`, komponen `Comparer` |
| [`../src/renderer/src/data/burp.ts`](../src/renderer/src/data/burp.ts) | `rawResponse`, `HTTP_HISTORY` (sumber contoh) |

## 5. Cara pakai

1. Buka **Comparer** (`/web/comparer`).
2. Edit **Item A** dan **Item B** (sudah terisi contoh 200 vs 403).
3. Klik **Compare**.
4. Baca ringkasan (added / removed / unchanged) dan daftar perbedaan baris (hijau `+`, merah `-`).

## 6. Batasan / temuan

- Diff tingkat **baris**, bukan karakter/kata.
- Tabel DP berukuran `O(n*m)` — teks sangat panjang bisa berat.
- Offline murni; tidak ada IPC/jaringan.
- Mengubah input menyetel ulang `compared=false` (harus klik Compare lagi).

## 7. Checklist pengerjaan

- [ ] Verifikasi `lineDiff` menghasilkan LCS benar pada contoh kecil.
- [ ] Uji statistik add/del/same cocok dengan hasil visual.
- [ ] Uji contoh default (200 vs 403) menampilkan perbedaan akses yang jelas.
- [ ] Uji teks identik → 0 added, 0 removed.

---
← [025 Decoder](025_decoder.md) · [Index](000_index.md) · [next: 027 Sequencer](027_sequencer.md) →
