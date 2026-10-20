import React, { useState } from 'react'
import TopBar from '../components/TopBar'
import { Panel, Disclaimer } from '../components/ui'
import { IconReport, IconDownload, IconRefresh } from '../components/icons'
import { MOCK_HOSTS, MOCK_VULNS, SEVERITY_ORDER } from '../data/mock'

function buildReport(operator: string): string {
  const now = new Date()
  const open = MOCK_VULNS.filter((v) => v.status !== 'mitigated')
  const bySev = SEVERITY_ORDER.map((s) => `  ${s.padEnd(9)} ${MOCK_VULNS.filter((v) => v.severity === s).length}`).join('\n')
  const hosts = MOCK_HOSTS.map((h) => `  ${h.ip.padEnd(13)} ${h.hostname.padEnd(26)} ${h.status.padEnd(9)} risk=${h.risk}`).join('\n')
  const top = open
    .sort((a, b) => b.cvss - a.cvss)
    .slice(0, 5)
    .map((v, i) => `  ${i + 1}. [${v.severity.toUpperCase()}] ${v.cve} ${v.title} (CVSS ${v.cvss}) — ${v.asset}`)
    .join('\n')

  return `RUY CYBERSECURITY PLATFORM — SECURITY POSTURE REPORT
====================================================
*** SIMULATED DEMONSTRATION DATA — NOT A REAL ASSESSMENT ***

Generated : ${now.toISOString()}
Operator  : ${operator || 'Operator'}
Scope     : RUY simulated lab estate (10.20.0.0/24)

SUMMARY
-------
  Monitored hosts        ${MOCK_HOSTS.length}
  Hosts responding       ${MOCK_HOSTS.filter((h) => h.status === 'up').length}
  Total findings         ${MOCK_VULNS.length}
  Open / unresolved      ${open.length}

FINDINGS BY SEVERITY
--------------------
${bySev}

TOP PRIORITY FINDINGS
---------------------
${top}

HOST INVENTORY
--------------
${hosts}

NOTE
----
This document was produced entirely from local, fabricated demo data inside the
RUY desktop prototype. No scanning, testing, or data collection was performed
against any real system or network.
`
}

export default function Reports() {
  const [operator] = useState(() => {
    try { return (JSON.parse(localStorage.getItem('ruy.v1.settings') || '{}').operatorName) || 'Operator' } catch { return 'Operator' }
  })
  const [report, setReport] = useState<string>('')
  const [generatedAt, setGeneratedAt] = useState<string>('')

  const generate = () => {
    setReport(buildReport(operator))
    setGeneratedAt(new Date().toLocaleString('en-GB'))
  }

  const download = (ext: 'txt' | 'json') => {
    const content =
      ext === 'json'
        ? JSON.stringify({ hosts: MOCK_HOSTS, findings: MOCK_VULNS, note: 'SIMULATED demo data', generated: new Date().toISOString() }, null, 2)
        : report || buildReport(operator)
    const blob = new Blob([content], { type: ext === 'json' ? 'application/json' : 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `RUY-report-${new Date().toISOString().slice(0, 10)}.${ext}`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <>
      <TopBar title="Reports" sub="Generate a simulated posture summary" />
      <div className="content page">
        <Disclaimer>
          Reports are compiled from the application's <strong>local demo data</strong>. Exported files are
          written only to the location you choose via the browser-style download dialog; nothing is uploaded.
        </Disclaimer>

        <Panel
          title="Posture Report"
          sub="Plaintext summary"
          className="mt-16"
          right={
            <div className="flex gap-12">
              <button className="btn btn-primary btn-sm" onClick={generate}><IconRefresh />{report ? 'Regenerate' : 'Generate'}</button>
              <button className="btn btn-sm" onClick={() => download('txt')}><IconDownload />.txt</button>
              <button className="btn btn-sm" onClick={() => download('json')}><IconDownload />.json</button>
            </div>
          }
        >
          {report ? (
            <>
              <div className="small muted mb-16">Generated {generatedAt}</div>
              <pre className="mono" style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: 12.5, lineHeight: 1.6, color: 'var(--silver-100)', background: 'var(--obsidian-800)', padding: 18, borderRadius: 8, border: '1px solid var(--line-soft)', maxHeight: 440, overflow: 'auto' }}>
                {report}
              </pre>
            </>
          ) : (
            <div className="empty"><IconReport /><div className="mt-8">No report yet. Click <strong>Generate</strong> to compile a simulated posture summary.</div></div>
          )}
        </Panel>
      </div>
    </>
  )
}
