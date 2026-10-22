// Stand-in for the `electron` module so main-process code runs under vitest.
// Paths live on globalThis because tests call vi.resetModules() to get fresh
// main-process state, which would otherwise also reset this module.
//
// Usage in a test file:
//   vi.mock('electron', async () => (await import('../helpers/electron-mock')).electron)

import { vi } from 'vitest'
import { mkdirSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

type Dirs = { userData: string; downloads: string; dialogPick: string | null }
const g = globalThis as unknown as { __interuDirs?: Dirs }
const dirs = (): Dirs => (g.__interuDirs ??= { userData: '', downloads: '', dialogPick: null })

/** New empty userData + downloads folders under the OS temp dir. */
export function freshDirs(): Dirs {
  const root = mkdtempSync(join(tmpdir(), 'interu-tc-'))
  const d = dirs()
  d.userData = join(root, 'userData')
  d.downloads = join(root, 'downloads')
  d.dialogPick = null
  mkdirSync(d.userData, { recursive: true })
  mkdirSync(d.downloads, { recursive: true })
  return d
}

/** Folder the mocked "open directory" dialog returns (null = user cancelled). */
export function pickFolder(path: string | null): void {
  dirs().dialogPick = path
}

export const electron = {
  app: { getPath: (name: string): string => (name === 'downloads' ? dirs().downloads : dirs().userData) },
  dialog: {
    showOpenDialog: vi.fn(async () => {
      const p = dirs().dialogPick
      return p ? { canceled: false, filePaths: [p] } : { canceled: true, filePaths: [] }
    })
  }
}

/** Load main-process modules with fresh module state (RoE cache, audit heads). */
export async function loadMain() {
  vi.resetModules()
  const audit = await import('../../src/main/audit')
  const evidence = await import('../../src/main/evidence')
  const http = await import('../../src/main/http')
  const proxy = await import('../../src/main/proxy')
  return { audit, evidence, http, proxy }
}
