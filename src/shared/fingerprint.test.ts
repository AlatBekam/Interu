import { describe, expect, it } from 'vitest'
import { FINGERPRINTS, detectProducts } from './fingerprint'
import { kevProductKnown } from './kev'

const ids = (hits: ReturnType<typeof detectProducts>) => hits.map((h) => h.fingerprint.id)

describe('fingerprint detection', () => {
  it('detects Apache HTTP Server from a scanner banner and captures its version', () => {
    const hits = detectProducts({ banner: 'Apache/2.4.58 (Unix)' })
    expect(ids(hits)).toEqual(['apache-httpd'])
    expect(hits[0].version).toBe('2.4.58')
  })

  it('maps Apache-Coyote to Tomcat only, never to Apache HTTP Server', () => {
    expect(ids(detectProducts({ banner: 'Apache-Coyote/1.1' }))).toEqual(['tomcat'])
    expect(ids(detectProducts({ headerText: 'Server: Apache-Coyote/1.1' }))).toEqual(['tomcat'])
  })

  it('detects IIS from a Server header and PHP from X-Powered-By', () => {
    expect(ids(detectProducts({ headerText: 'Server: Microsoft-IIS/8.5\nX-Powered-By: PHP/5.3.3' })).sort())
      .toEqual(['iis', 'php'])
    expect(detectProducts({ headerText: 'X-Powered-By: PHP/5.3.3' })[0].version).toBe('5.3.3')
  })

  it('detects WordPress from the HTML generator meta tag', () => {
    const body = '<html><head><meta name="generator" content="WordPress 6.4.2" /></head></html>'
    const hits = detectProducts({ body })
    expect(ids(hits)).toEqual(['wordpress'])
    expect(hits[0].version).toBe('6.4.2')
  })

  it('stays silent for products with no KEV entries (nginx, OpenSSH)', () => {
    expect(detectProducts({ banner: 'nginx/1.25.3' })).toEqual([])
    expect(detectProducts({ banner: 'SSH-2.0-OpenSSH_9.6p1' })).toEqual([])
  })
})

describe('fingerprint keys stay in sync with the KEV snapshot', () => {
  // Drift guard: a refresh that renames a vendor or product fails here, loudly.
  it('every kevProducts key exists in the committed snapshot', () => {
    const missing = FINGERPRINTS.flatMap((f) =>
      f.kevProducts.filter((k) => !kevProductKnown(k)).map((k) => `${f.id}: ${k}`)
    )
    expect(missing).toEqual([])
  })
})
