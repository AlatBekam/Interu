// Launch the built Interu app in a real Electron window for E2E tests.
// userData and Downloads point at throwaway temp folders (RUY_USERDATA_DIR /
// RUY_DOWNLOADS_DIR hooks in src/main/index.ts), so the operator's real data
// is never touched.

import { _electron, type ElectronApplication, type Page } from 'playwright-core'
import { mkdirSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

export const ROOT = fileURLToPath(new URL('../../..', import.meta.url))
const SHOTS = join(ROOT, 'testcase', 'results', 'screenshots')

export interface RunningApp {
  app: ElectronApplication
  page: Page
  userData: string
  downloads: string
  pageErrors: string[]
  close(): Promise<void>
}

export async function launchApp(): Promise<RunningApp> {
  const root = mkdtempSync(join(tmpdir(), 'interu-e2e-'))
  const userData = join(root, 'userData')
  const downloads = join(root, 'downloads')
  mkdirSync(userData, { recursive: true })
  mkdirSync(downloads, { recursive: true })

  // ELECTRON_RUN_AS_NODE leaks in when the shell itself runs under Electron
  // (e.g. an editor terminal); with it set, electron.exe would run as plain Node.
  const env: Record<string, string> = {}
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && k !== 'ELECTRON_RUN_AS_NODE') env[k] = v
  env.RUY_USERDATA_DIR = userData
  env.RUY_DOWNLOADS_DIR = downloads

  const app = await _electron.launch({
    executablePath: join(ROOT, 'node_modules', 'electron', 'dist', 'electron.exe'),
    args: ['.'],
    cwd: ROOT,
    env
  })
  const page = await app.firstWindow()
  const pageErrors: string[] = []
  page.on('pageerror', (e) => pageErrors.push(e.message))
  await page.waitForLoadState('domcontentloaded')
  return { app, page, userData, downloads, pageErrors, close: () => app.close() }
}

/** Make the next "open folder" dialog in the main process return `dir`. */
export async function mockFolderDialog(app: ElectronApplication, dir: string): Promise<void> {
  await app.evaluate(({ dialog }, picked) => {
    dialog.showOpenDialog = (async () => ({ canceled: false, filePaths: [picked] })) as typeof dialog.showOpenDialog
  }, dir)
}

export async function shot(page: Page, name: string): Promise<void> {
  mkdirSync(SHOTS, { recursive: true })
  await page.screenshot({ path: join(SHOTS, `${name}.png`) })
}

/** Click a sidebar entry by its visible label. */
export async function nav(page: Page, label: string): Promise<void> {
  await page.locator('nav').getByText(label, { exact: true }).click()
}
