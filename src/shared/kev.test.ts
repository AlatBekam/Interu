import { describe, expect, it } from 'vitest'
import { isKev, kevFor } from './kev'
import { analyzeScan } from './rules'
import type { ScanHost } from './scan'

const host = (ip: string, port: number, service: string, version: string): ScanHost => ({
  ip, status: 'up', tookMs: 1,
  openPorts: [{ port, service, state: 'open', version }]
})

describe('kevFor', () => {
  it('returns KEV info for a CVE in the catalog', () => {
    const [hit] = kevFor(['CVE-2021-44228'])
    expect(hit.cve).toBe('CVE-2021-44228')
    expect(hit.dateAdded).toMatch(/^\d{4}-\d{2}-\d{2}$/)
  })
  it('returns nothing for a CVE not in the catalog or no input', () => {
    expect(kevFor(['CVE-1999-0001'])).toEqual([])
    expect(kevFor(undefined)).toEqual([])
    expect(isKev(['CVE-1999-0001'])).toBe(false)
    expect(isKev(['CVE-2021-44228'])).toBe(true)
  })
})

describe('KEV enrichment on scan findings', () => {
  it('attaches kev to a banner→CVE finding whose CVE is actively exploited', () => {
    const f = analyzeScan([host('10.0.0.5', 80, 'http', 'Apache/2.4.49 (Unix)')])
      .find((x) => x.templateId === 'banner-apache-traversal')
    expect(f).toBeDefined()
    expect(f!.kev?.map((k) => k.cve)).toContain('CVE-2021-41773')
  })
  it('leaves kev unset when the CVE is not in KEV', () => {
    const f = analyzeScan([host('10.0.0.6', 21, 'ftp', '220 (vsFTPd 2.3.4)')])
      .find((x) => x.templateId === 'banner-vsftpd-234')
    expect(f).toBeDefined()
    expect(f!.kev).toBeUndefined()
  })
})

describe('new banner templates (KEV-listed CVEs)', () => {
  it('matches ProFTPD 1.3.5 and tags CVE-2015-3306 as KEV', () => {
    const f = analyzeScan([host('10.0.0.7', 21, 'ftp', '220 ProFTPD 1.3.5 Server')])
      .find((x) => x.templateId === 'banner-proftpd-135')
    expect(f?.cve).toEqual(['CVE-2015-3306'])
    expect(f?.kev?.length).toBe(1)
  })
  it('matches Exim 4.91 and not 4.92', () => {
    const hit = (v: string) => analyzeScan([host('10.0.0.8', 25, 'smtp', `220 mx ESMTP Exim ${v}`)])
      .some((x) => x.templateId === 'banner-exim-cve-2019-10149')
    expect(hit('4.91')).toBe(true)
    expect(hit('4.92')).toBe(false)
  })
  it('matches IIS 6.0 and not IIS 7.5', () => {
    const hit = (s: string) => analyzeScan([host('10.0.0.9', 80, 'http', s)])
      .some((x) => x.templateId === 'banner-iis6-webdav')
    expect(hit('Microsoft-IIS/6.0')).toBe(true)
    expect(hit('Microsoft-IIS/7.5')).toBe(false)
  })
})
