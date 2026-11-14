import { describe, expect, it } from 'vitest'
import { MODERN_BACKUP_RULES } from './rulepack2025'
import { TEMPLATES, computeBaseline, matchActive } from './rules'
import { activeTemplates } from './rules'
import type { HttpRes } from './http'

const response = (body: string): HttpRes => ({ ok: true, status: 200, body, rawHeaders: 'content-type: text/plain', raw: `HTTP/1.1 200 OK\r\n\r\n${body}`, timingMs: 1, size: body.length })

describe('modern backup rule pack', () => {
  it('adds 300 distinct backup paths to the original 408 templates', () => {
    expect(MODERN_BACKUP_RULES).toHaveLength(300)
    expect(TEMPLATES).toHaveLength(808)
    expect(new Set(TEMPLATES.map(r => r.id)).size).toBe(TEMPLATES.length)
    expect(new Set(MODERN_BACKUP_RULES.map(r => r.request?.path)).size).toBe(300)
    expect(MODERN_BACKUP_RULES.every(r => r.kind === 'http-active' && r.request?.method === 'GET' && r.matchers.some(m => m.part === 'body'))).toBe(true)
  })
  it('uses one catalogue regardless of target', () => {
    expect(activeTemplates()).toHaveLength(733)
  })
  it('requires file-specific content, and demotes a matching catch-all page', () => {
    const rule = MODERN_BACKUP_RULES.find(r => r.id === 'modern-backup-npmrc-1')!
    const url = 'https://target.test/.npmrc.bak'
    expect(matchActive(rule, url, response('<html>login</html>'))).toBeNull()
    const hit = matchActive(rule, url, response('//registry.npmjs.org/:_authToken=example'), { baseline: computeBaseline(response('not found')) })
    expect(hit?.confidence).toBe('confirmed')
    const catchAll = matchActive(rule, url, response('//registry.npmjs.org/:_authToken=example'), { baseline: computeBaseline(response('//registry.npmjs.org/:_authToken=example')) })
    expect(catchAll?.confidence).toBe('suspected')
  })
})
