# 027 — Sequencer

← [026 — Comparer](026_comparer.md) · [Index](000_index.md) · [030 — Operations & Analysis (Pengantar Kelompok)](030_operations.md) →

## 1. Status

✅ **NYATA** — menganalisa token yang **di-paste operator** (satu per baris); perhitungan entropi nyata dan offline.

## 2. Tujuan fitur

Menilai keacakan (randomness) token sesi/CSRF dengan entropi Shannon — seperti Sequencer di Burp. Menampilkan entropi per-karakter, estimasi per-token, skor kualitas, dan entropi per-posisi.

## 3. Cara kerja

- **Sumber token:** textarea "Tokens" (disimpan di `usePersistentState('sequencer.tokens')`). `parseTokens(text)` ([`../src/shared/tokens.ts`](../src/shared/tokens.ts)) men-trim, membuang baris kosong, dan menghapus duplikat dengan urutan tetap. Tombol **Analyze** aktif bila ada minimal 2 token unik.
- **Entropi global:** `analyzeTokens(tokens)` (mengembalikan `null` bila < 2 token) menghitung entropi Shannon bit/karakter atas distribusi karakter gabungan seluruh token.
- **Langit-langit:** ditentukan dari charset yang terdeteksi — hanya digit = 10 simbol, hex = 16, base64url `[A-Za-z0-9_-]` = 64, selain itu printable = 94. `qualityPct` = bit/karakter ÷ log2(ukuran charset) × 100; verdict Excellent/Good/Poor/Weak dari ambang 90/75/55.
- **Per-posisi:** entropi per posisi dihitung atas token yang punya posisi itu, hingga 64 posisi → divisualkan sebagai bar. `Gauge` memakai tone `quality` (tinggi = bagus = hijau).

## 4. File terkait

| File | Fungsi utama |
|------|--------------|
| [`../src/renderer/src/pages/web/Sequencer.tsx`](../src/renderer/src/pages/web/Sequencer.tsx) | UI: textarea token, `Analyze`, kartu Stat, `Gauge`, bar per-posisi |
| [`../src/shared/tokens.ts`](../src/shared/tokens.ts) | `parseTokens`, `analyzeTokens` (logika murni) |
| [`../src/shared/tokens.test.ts`](../src/shared/tokens.test.ts) | Tes unit logika di atas |

## 5. Cara pakai

1. Buka **Sequencer** (`/web/sequencer`).
2. Tempel token (session ID, CSRF, dll. dari pengujian berizin), satu per baris.
3. Klik **Analyze**.
4. Baca kartu: Entropy/char, Entropy/token, Quality (%), dan grafik Per-position Entropy.

## 6. Batasan / temuan

- Token **tidak** ditangkap otomatis dari target; operator menempelkannya. Pakai minimal beberapa puluh token agar hasil bermakna.
- Entropi menganggap karakter independen; tidak menguji pola kriptografis lanjutan.
- Tidak ada IPC/jaringan.

## 7. Checklist pengerjaan

- [x] Logika murni di `src/shared/tokens.ts` dengan tes `tokens.test.ts`.
- [ ] Uji `qualityPct` dan verdict pada beberapa set token (digit, hex, base64url, campuran).
- [ ] Konfirmasi grafik per-posisi menggambar satu bar per posisi (maks 64).
- [ ] (Lanjut) isi token otomatis dari hasil tangkapan Proxy.

---
← [026 Comparer](026_comparer.md) · [Index](000_index.md) · [next: 030 Operations](030_operations.md) →
