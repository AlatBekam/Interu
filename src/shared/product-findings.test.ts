import { describe, expect, it } from 'vitest'
import { analyzeHttpResponse, analyzeScan } from './rules'
import type { ProxyLogEntry } from './proxy'
import type { ScanHost } from './scan'

const scanHost = (version: string, port = 80): ScanHost => ({
  ip: '10.0.0.40', status: 'up', tookMs: 1,
  openPorts: [{ port, service: 'http', state: 'open', version }]
})

const proxy = (headers: string): ProxyLogEntry => ({
  id: 1, time: '', method: 'GET', host: 'shop.test', path: '/', url: 'https://shop.test/', status: 200, ms: 1, kind: 'http',
  response: `HTTP/1.1 200 OK\r\n${headers}\r\n\r\nok`
})

describe('product findings from scanner banners', () => {
  it('adds a suspected, version-blind product finding with its KEV CVEs', () => {
    const f = analyzeScan([scanHost('Apache/2.4.58 (Unix)')]).find((x) => x.templateId === 'kev-product-apache-httpd')
    expect(f).toBeDefined()
    expect(f!.confidence).toBe('suspected')
    expect(f!.severity).toBe('medium')
    expect(f!.tags).toContain('kev-product')
    expect(f!.kev!.length).toBeGreaterThan(0)
    expect(f!.name.endsWith('(version not verified)')).toBe(true)
  })

  it('does not repeat CVEs that a precise template already reported on the same port', () => {
    const findings = analyzeScan([scanHost('Apache/2.4.49 (Unix)')])
    const precise = findings.find((x) => x.templateId === 'banner-apache-traversal')
    expect(precise?.cve).toEqual(['CVE-2021-41773', 'CVE-2021-42013'])
    const product = findings.find((x) => x.templateId === 'kev-product-apache-httpd')
    if (product) {
      expect(product.cve).not.toContain('CVE-2021-41773')
      expect(product.cve).not.toContain('CVE-2021-42013')
    }
  })

  it('adds nothing for a product that has no KEV entries', () => {
    expect(analyzeScan([scanHost('nginx/1.25.3')]).filter((x) => x.templateId.startsWith('kev-product-'))).toEqual([])
  })
})

describe('product findings from proxy responses', () => {
  it('reports one finding per product per origin from headers', () => {
    const findings = analyzeHttpResponse(proxy('Server: Microsoft-IIS/8.5\r\nX-Powered-By: PHP/5.3.3'))
    const ids = findings.map((f) => f.templateId)
    expect(ids.filter((id) => id === 'kev-product-iis')).toHaveLength(1)
    expect(ids.filter((id) => id === 'kev-product-php')).toHaveLength(1)
    expect(findings.find((f) => f.templateId === 'kev-product-iis')!.target).toBe('https://shop.test')
  })
})
