import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

// E2E runs the BUILT app (out/) in a real Electron window, so it is kept out of
// `npm test`. Run with `npm run test:e2e` (builds first).
export default defineConfig({
  test: {
    root: fileURLToPath(new URL('../..', import.meta.url)),
    include: ['testcase/e2e/**/*.e2e.ts'],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    fileParallelism: false
  }
})
