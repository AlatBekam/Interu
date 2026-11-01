// Lists the CISA KEV products that no curated fingerprint covers, most CVEs first.
// Read-only: it parses the committed fingerprint table and the KEV snapshot; no network.
// Usage: npm run kev:coverage [N]   (N = how many uncovered products to show, default 15)
// Limitation: fingerprint keys are read by pattern from src/shared/fingerprint.ts
// (the quoted strings inside each kevProducts array). Reformatting those arrays
// needs a matching change here.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const read = (name) => readFileSync(fileURLToPath(new URL(`../src/shared/${name}`, import.meta.url)), 'utf8')
const limit = Number(process.argv[2] ?? 15)

const covered = new Set()
for (const m of read('fingerprint.ts').matchAll(/kevProducts:\s*\[([^\]]*)\]/g)) {
  for (const s of m[1].matchAll(/'([^']*)'/g)) covered.add(s[1])
}

const snapshot = read('kev-index.ts')
const kev = JSON.parse(snapshot.slice(snapshot.indexOf('{', snapshot.indexOf('KEV: Record'))))

const counts = new Map()
for (const e of Object.values(kev)) {
  const key = `${e.vendor}|${e.product}`
  counts.set(key, (counts.get(key) ?? 0) + 1)
}

const uncovered = [...counts]
  .filter(([key]) => !covered.has(key))
  .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))

for (const [key, n] of uncovered.slice(0, limit)) {
  console.log(`${String(n).padStart(4)}  ${key}`)
}
const hit = [...counts.keys()].filter((key) => covered.has(key)).length
console.log(`covered ${hit} of ${counts.size} products`)
