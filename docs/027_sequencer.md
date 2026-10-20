# 027 — Sequencer

← [026 — Comparer](026_comparer.md) · [Index](000_index.md) · [030 — Operations & Analysis (Pengantar Kelompok)](030_operations.md) →

## 1. Status

🟡 **SEBAGIAN** — matematika entropi **nyata**, tetapi token **dibuat lokal** (bukan ditangkap dari target).

## 2. Tujuan fitur

Menilai keacakan (randomness) token sesi/CSRF dengan entropi Shannon — seperti Sequencer di Burp. Menampilkan entropi per-karakter, estimasi per-token, skor kualitas, dan entropi per-posisi.

## 3. Cara kerja

- **Sumber token:** `sampleTokens(n)` ([`../src/renderer/src/data/burp.ts`](../src/renderer/src/data/burp.ts)) menghasilkan `n` token 20 karakter dari alfabet 62-char memakai LCG ter-seed (`seed = 1337`) — **deterministik & lokal**, tidak ada capture dari jaringan.
- **Entropi global:** `shannonBitsPerChar(tokens)` ([`../src/renderer/src/pages/web/Sequencer.tsx`](../src/renderer/src/pages/web/Sequencer.tsx)) menghitung `H = -Σ p·log2(p)` atas distribusi karakter seluruh token.
- **Turunan:** `perToken = bpc * 20`; `qualityPct = min(100, round(bpc / log2(62) * 100))` (langit-langit alfabet 62-char ≈ 5.95 bit); verdict Excellent/Good/Poor/Weak dari ambang 90/75/55.
- **Per-posisi:** entropi dihitung terpisah untuk tiap dari 20 slot karakter → divisualkan sebagai bar.

## 4. File terkait

| File | Fungsi utama |
|------|--------------|
| [`../src/renderer/src/pages/web/Sequencer.tsx`](../src/renderer/src/pages/web/Sequencer.tsx) | `shannonBitsPerChar`, `bpc`, `qualityPct`, `positional` |
| [`../src/renderer/src/data/burp.ts`](../src/renderer/src/data/burp.ts) | `sampleTokens` (LCG seed 1337) |

## 5. Cara pakai

1. Buka **Sequencer** (`/web/sequencer`).
2. Pilih **Sample size** (50 / 100 / 200 / 500 token).
3. Klik **Analyze**.
4. Baca kartu: Entropy/char, Entropy/token, Quality (%), dan grafik Per-position Entropy.

## 6. Batasan / temuan

- Token **tidak** ditangkap dari target — dibuat `sampleTokens` secara lokal & deterministik (hasil sama tiap jalan karena seed tetap).
- Semua token 20 karakter; panjang tetap.
- Entropi menganggap karakter independen; tidak menguji pola kriptografis lanjutan.
- Tidak ada IPC/jaringan.

## 7. Checklist pengerjaan

- [ ] Verifikasi `sampleTokens` deterministik (seed 1337) dan panjang 20.
- [ ] Verifikasi `shannonBitsPerChar` pada distribusi dikenal (mis. uniform 62 char ≈ 5.95 bit).
- [ ] Uji `qualityPct` dan verdict pada beberapa ukuran sampel.
- [ ] Konfirmasi grafik per-posisi menggambar 20 bar.
- [ ] (Lanjut) sambungkan sumber token dari hasil tes resmi, bukan generator lokal.

---
← [026 Comparer](026_comparer.md) · [Index](000_index.md) · [next: 030 Operations](030_operations.md) →
