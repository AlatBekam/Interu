import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

// Keeps the visual system consistent: colour comes from tokens in global.css, nothing is
// decorated with gradients, glow or blur, and no emoji appears in the UI.
const root = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')
const css = readFileSync(join(root, 'styles/global.css'), 'utf8')

function tsxFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n)
    return statSync(p).isDirectory() ? tsxFiles(p) : p.endsWith('.tsx') ? [p] : []
  })
}
// The crest is brand artwork and icons are stroke art: both may carry their own colours.
const ART = ['components/Crest.tsx', 'components/icons.tsx']
const files = tsxFiles(root).filter((f) => !ART.some((a) => relative(root, f).replace(/\\/g, '/') === a))

describe('visual consistency', () => {
  it('global.css has no gradients, blur or glow', () => {
    expect(css).not.toMatch(/linear-gradient|radial-gradient|conic-gradient|backdrop-filter|drop-shadow/)
  })

  it('box-shadow is used only by the floating context menu', () => {
    const uses = css.split('\n').filter((l) => /box-shadow/.test(l))
    expect(uses.every((l) => l.includes('rgba(0, 0, 0, 0.35)'))).toBe(true)
    expect(uses.length).toBeLessThanOrEqual(1)
  })

  it('global.css has no hard-coded colour outside the token blocks and the one menu shadow', () => {
    const body = css.replace(/:root(\[data-theme='light'\])? \{[^}]*\}/g, '')
    expect(body.match(/#[0-9a-fA-F]{3,8}\b/g) ?? []).toEqual([])
    expect((body.match(/rgba?\(/g) ?? []).length).toBeLessThanOrEqual(1)
  })

  it.each(files.map((f) => [relative(root, f).replace(/\\/g, '/'), f]))('%s has no hard-coded colour or emoji', (_n, f) => {
    const src = readFileSync(f, 'utf8')
    expect(src.match(/#[0-9a-fA-F]{6}\b|#[0-9a-fA-F]{3}\b(?![0-9a-zA-Z-])|rgba?\(/g) ?? [], 'colour literal').toEqual([])
    expect(src.match(/[⛔⚠✓✔➤⏸✕❌🔒]/gu) ?? [], 'emoji / dingbat').toEqual([])
  })
})
