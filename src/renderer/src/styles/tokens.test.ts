import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

// Guards the design tokens in global.css: every text/state colour must stay readable
// (WCAG AA, 4.5:1) on every surface, in both themes.
const css = readFileSync(new URL('./global.css', import.meta.url), 'utf8')

function block(selector: string): string {
  const i = css.indexOf(selector + ' {')
  if (i < 0) throw new Error(`block not found: ${selector}`)
  return css.slice(i, css.indexOf('}', i))
}

function tokens(selector: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const m of block(selector).matchAll(/--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)) out[m[1]] = m[2]
  return out
}

const lum = (hex: string): number => {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4))
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]
}
const ratio = (a: string, b: string): number => {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}

const TEXT = ['fg', 'fg-2', 'fg-3', 'accent', 'crit', 'high', 'med', 'low', 'info', 'ok']
const SURFACES = ['bg', 'surface', 'raised']

describe.each([
  ['dark', ':root'],
  ['light', ":root[data-theme='light']"]
])('%s theme tokens', (_name, selector) => {
  const t = tokens(selector)

  it('defines every role', () => {
    for (const k of [...TEXT, ...SURFACES, 'on-accent']) expect(t[k], k).toBeDefined()
  })

  it.each(TEXT)('%s is >= 4.5:1 on every surface', (token) => {
    for (const s of SURFACES) {
      expect(ratio(t[token], t[s]), `${token} on ${s}`).toBeGreaterThanOrEqual(4.5)
    }
  })

  it('text on the accent fill (primary button) is >= 4.5:1', () => {
    expect(ratio(t['on-accent'], t.accent)).toBeGreaterThanOrEqual(4.5)
  })
})
