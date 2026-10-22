# testcase/

Tempat semua **use case (UC)** dan **test case (TC)** Interu. Daftar lengkap beserta statusnya ada di [CATALOG.md](CATALOG.md).

## Menjalankan

```bash
npm test                         # semua test: unit (src/shared) + integration (testcase/)
npx vitest run testcase          # hanya folder ini
npx vitest run -t "TC-03"        # satu use case / test case berdasarkan ID
npm run typecheck                # testcase/ ikut dicek
```

## Struktur

| Folder | Isi |
| --- | --- |
| `integration/` | Menjalankan modul **main process sungguhan** (`src/main/*`) dengan disk sungguhan di folder sementara |
| `helpers/electron-mock.ts` | Pengganti modul `electron`: `app.getPath` → folder tmp, `dialog.showOpenDialog` → folder pilihan test |
| `helpers/target-server.ts` | Server HTTP uji lokal (hanya `127.0.0.1`, port acak). Disiapkan untuk uji manual/E2E; belum dipakai test otomatis |

Unit test logika murni tetap berada di samping kodenya (`src/shared/*.test.ts`) dan dicatat di katalog.

## Konvensi ID

- `UC-xx`: satu use case (alur yang dilakukan operator), mis. `UC-03 Paket bukti`.
- `TC-xx-yy`: test case ke-`yy` dari `UC-xx`. ID ini ditulis di awal nama `it(...)` supaya bisa difilter dengan `-t`.
- Test yang memastikan **batasan yang sudah terdokumentasi** diberi label `KNOWN LIMIT`. Kalau batasan itu diperbaiki, test-nya ikut diubah.

## Menambah integration test

```ts
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { freshDirs, loadMain } from '../helpers/electron-mock'

vi.mock('electron', async () => (await import('../helpers/electron-mock')).electron)

describe('UC-xx Nama use case', () => {
  let m: Awaited<ReturnType<typeof loadMain>>
  beforeEach(async () => {
    freshDirs()          // userData + downloads baru di %TEMP%
    m = await loadMain() // modul main dengan state bersih (cache RoE, head audit)
  })

  it('TC-xx-01 ...', () => {
    m.audit.setRoe({ operation: 'OP-TC', operator: 'tester', allow: { scan: true } })
    expect(m.audit.authorize('scan', '127.0.0.1').ok).toBe(true)
  })
})
```

- Panggil `loadMain()` sekali lagi **tanpa** `freshDirs()` untuk mensimulasikan restart aplikasi.
- Setelah menambah test, perbarui [CATALOG.md](CATALOG.md).
