# 025 — Decoder

← [024 — Target / Content Discovery](024_target-discovery.md) · [Index](000_index.md) · [026 — Comparer](026_comparer.md) →

## 1. Status

✅ **NYATA** — transform encode/decode berjalan **sepenuhnya offline**; utilitas sungguhan tanpa jaringan.

## 2. Tujuan fitur

Meng-encode dan men-decode teks dengan lima skema: **URL, Base64, Hex, HTML entities, ASCII** — berguna untuk menyiapkan/membaca payload. Tidak ada data yang keluar dari aplikasi.

## 3. Cara kerja

Fungsi murni `apply(op, mode, input)` ([`../src/renderer/src/pages/web/Decoder.tsx`](../src/renderer/src/pages/web/Decoder.tsx)) dibungkus `try/catch` yang mengembalikan pesan ⚠ bila input invalid:

| Op | Encode | Decode |
|----|--------|--------|
| `url` | `encodeURIComponent` | `decodeURIComponent` |
| `base64` | `btoa(unescape(encodeURIComponent(x)))` | `decodeURIComponent(escape(atob(x)))` |
| `hex` | charCode → hex 2-digit, dipisah spasi | ambil `[0-9a-fA-F]`, pasangan → char |
| `html` | ganti `& < > " '` ke entitas | balikkan `&amp; &lt; &gt; &quot; &#39;` |
| `ascii` | charCode desimal dipisah spasi | split spasi → `fromCharCode` |

Output dihitung setiap render (`output = apply(op, mode, input)`). Tombol **Chain** menyalin output menjadi input; **Copy** menyalin ke clipboard.

## 4. File terkait

| File | Fungsi utama |
|------|--------------|
| [`../src/renderer/src/pages/web/Decoder.tsx`](../src/renderer/src/pages/web/Decoder.tsx) | `apply`, `htmlEntities`, `OPS`, komponen `Decoder` |

## 5. Cara pakai

1. Buka **Decoder** (`/web/decoder`).
2. Pilih skema (URL / Base64 / Hex / HTML / ASCII).
3. Pilih **Encode** atau **Decode**.
4. Ketik di panel **Input**; hasil langsung muncul di **Output**.
5. Gunakan **Chain** untuk merantai transform, atau **Copy** untuk menyalin hasil.

## 6. Batasan / temuan

- Semua offline; tidak ada IPC/jaringan.
- Base64/escape memakai pola `unescape`/`escape` lama agar UTF-8 aman di `btoa`/`atob`.
- Input invalid (mis. Base64 rusak) menghasilkan pesan "⚠ cannot …", bukan throw.

## 7. Checklist pengerjaan

- [ ] Verifikasi tiap pasangan encode→decode kembali ke teks semula (URL, Base64, Hex, HTML, ASCII).
- [ ] Uji input UTF-8 (non-ASCII) pada Base64.
- [ ] Uji input invalid → pesan ⚠ muncul, aplikasi tidak crash.
- [ ] Konfirmasi tombol Chain dan Copy bekerja.

---
← [024 Target / Discovery](024_target-discovery.md) · [Index](000_index.md) · [next: 026 Comparer](026_comparer.md) →
