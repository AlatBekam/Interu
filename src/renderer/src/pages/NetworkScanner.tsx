import React, { useEffect, useRef, useState } from 'react'
import TopBar from '../components/TopBar'
import { Panel, Disclaimer, Meter } from '../components/ui'
import { IconPlay, IconStop, IconScan } from '../components/icons'
import ScopeBar from '../components/ScopeBar'
import { usePersistentState, useSettings } from '../store/store'
import { profilePorts, ScanHost, ScanEvent, ScanProfile, ScanSummary } from '../../../shared/scan'
import { analyzeScan } from '../../../shared/rules'
import { addFindings } from '../store/findings'
import { pushActivity, noteScopeBlock } from '../store/activity'

type Phase = 'idle' | 'scanning' | 'done'

interface DisplayHost {
  ip: string
  hostname: string
  os: string
  status: string
  open: { port: number; service: string; state: string; version: string }[]
}

const liveToDisplay = (h: ScanHost): DisplayHost => ({
  ip: h.ip,
  hostname: '—',
  os: '—',
  status: h.status,
  open: h.openPorts.map((p) => ({ port: p.port, service: p.service, state: p.state, version: p.version || '—' }))
})

const hasBridge = typeof window !== 'undefined' && !!window.ruy?.scan

export default function NetworkScanner() {
  const [settings] = useSettings()
  const [target, setTarget] = usePersistentState('scanner.target', '127.0.0.1')
  const [profile, setProfile] = usePersistentState<ScanProfile>('scanner.profile', 'quick')
  const [phase, setPhase] = useState<Phase>('idle')
  const [progress, setProgress] = useState(0)
  const [found, setFound] = useState<DisplayHost[]>([])
  const [log, setLog] = useState<string[]>([])
  const [note, setNote] = useState<string | null>(null)
  const [summary, setSummary] = useState<ScanSummary | null>(null)

  const scanIdRef = useRef<number>(0)
  const runRef = useRef(0)
  const offProgress = useRef<(() => void) | null>(null)

  // Subscribe once to live progress events; filter by the active scan id.
  useEffect(() => {
    if (!hasBridge) return
    offProgress.current = window.ruy!.scan.onProgress((ev: ScanEvent) => {
      if (ev.scanId !== scanIdRef.current) return
      switch (ev.type) {
        case 'start':
          setLog((l) => [...l, ev.message])
          break
        case 'log':
          setLog((l) => (l.length > 400 ? [...l.slice(-400), ev.message] : [...l, ev.message]))
          break
        case 'progress':
          setProgress(ev.percent)
          break
        case 'host':
          setFound((f) => [...f, liveToDisplay(ev.host)])
          break
        case 'error':
          setLog((l) => [...l, `> error: ${ev.error}`])
          break
        case 'done':
          setProgress(100)
          break
      }
    })
    return () => { offProgress.current?.(); offProgress.current = null }
  }, [])

  // On leave: cancel any scan still running in main.
  useEffect(() => () => {
    if (scanIdRef.current) void window.ruy?.scan?.cancel(scanIdRef.current)
    scanIdRef.current = 0
  }, [])

  const startLive = async () => {
    if (!window.ruy?.scan) return
    setNote(null)
    setSummary(null)
    setFound([])
    setProgress(0)
    setLog([`> starting TCP connect scan of ${target} — ${profile} profile`])
    setPhase('scanning')
    const run = ++runRef.current
    const id = Date.now()
    scanIdRef.current = id
    try {
      pushActivity({ ts: new Date().toISOString(), level: 'info', category: 'scan', message: `Scan started: ${target} (${profile})`, target })
      const res = await window.ruy.scan.run({ target, profile }, settings.scope, id)
      // A newer scan started meanwhile: don't let this result overwrite it.
      if (runRef.current !== run) return
      if (!res.ok) {
        if (res.blocked) noteScopeBlock(target, 'scan')
        setNote(res.blocked ? `⛔ ${res.error}` : `⚠️ ${res.error}`)
        setLog((l) => [...l, `> ${res.error}`])
        setPhase('idle')
        setProgress(0)
        return
      }
      // The resolved result is authoritative (covers hosts that streamed late).
      if (res.hosts) setFound(res.hosts.map(liveToDisplay))
      if (res.summary) {
        setSummary(res.summary)
        pushActivity({ ts: new Date().toISOString(), level: 'ok', category: 'scan', message: `Scan finished: ${res.summary.hostsUp} host(s) up, ${res.summary.openPortCount} open port(s)`, target })
      }
      // Feed the Rule Engine with real open-port/banner signals.
      if (res.hosts && res.hosts.length) {
        const added = addFindings(analyzeScan(res.hosts))
        if (added > 0) setLog((l) => [...l, `> rule engine: ${added} new finding(s) — see Rule Engine / Vulnerabilities`])
      }
      setPhase('done')
    } catch (e) {
      if (runRef.current !== run) return
      setNote(`⚠️ ${(e as Error).message}`)
      setPhase('idle')
    }
  }

  const stop = () => {
    if (window.ruy?.scan && scanIdRef.current) window.ruy.scan.cancel(scanIdRef.current)
    scanIdRef.current = 0
    setPhase('done')
  }

  const portCount = profilePorts(profile).length
  const scanning = phase === 'scanning'

  return (
    <>
      <TopBar title="Network Scanner" sub="Real TCP connect scan (scope-gated)" />
      <div className="content page">
        <Disclaimer>
          <strong>Opens real TCP connections.</strong> Only targets inside your Authorized scope are
          scanned — add the host or subnet (e.g. <span className="mono">10.20.0.0/24</span>) below. Use this only
          against systems you own or are authorized to test.
        </Disclaimer>
        {!hasBridge && <div className="small mt-12" style={{ color: 'var(--danger, #d6594f)' }}>Scanner bridge unavailable: run Interu as the desktop app to scan.</div>}

        <div className="mt-16"><ScopeBar /></div>

        <Panel title="Scan Configuration" className="mt-16">
          <div className="grid grid-3" style={{ alignItems: 'end' }}>
            <label className="field">
              <span className="lab">Target (IP / CIDR / range)</span>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={scanning}
                placeholder="127.0.0.1  /  10.20.0.0/24  /  10.0.0.1-50"
              />
            </label>
            <label className="field">
              <span className="lab">Profile — {portCount} ports</span>
              <select value={profile} onChange={(e) => setProfile(e.target.value as ScanProfile)} disabled={scanning}>
                <option value="quick">Quick (top 100 ports)</option>
                <option value="standard">Standard (common ports)</option>
                <option value="deep">Deep (common ports + version)</option>
              </select>
            </label>
            <div className="flex gap-12">
              {!scanning ? (
                <button className="btn btn-primary" onClick={() => void startLive()} disabled={!hasBridge}><IconPlay />Run Scan</button>
              ) : (
                <button className="btn btn-danger" onClick={stop}><IconStop />Stop</button>
              )}
            </div>
          </div>

          {note && <div className="small mt-12" style={{ color: 'var(--danger, #d6594f)' }}>{note}</div>}

          {phase !== 'idle' && (
            <div className="mt-24">
              <div className="flex justify-between small muted" style={{ marginBottom: 6 }}>
                <span>{scanning ? 'Scanning…' : summary?.cancelled ? 'Stopped' : 'Complete'}</span>
                <span className="mono">{progress}%</span>
              </div>
              <Meter value={progress} tone={phase === 'done' ? 'ok' : undefined} />
              {summary && (
                <div className="small muted mt-12">
                  {summary.hostsUp} host up · {summary.openPortCount} open port · {summary.totalIps} IP × {summary.totalPorts} port · {(summary.tookMs / 1000).toFixed(1)}s
                  {summary.cancelled ? ' · cancelled' : ''}
                </div>
              )}
            </div>
          )}
        </Panel>

        <div className="grid grid-2 mt-24">
          <Panel title="Discovered Hosts" sub={`${found.length} up`} right={<IconScan />}>
            {found.length === 0 ? (
              <div className="empty">{scanning ? 'Scanning…' : 'No hosts yet. Run a scan to populate results.'}</div>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Open</th><th>State</th></tr></thead>
                  <tbody>
                    {found.map((h) => (
                      <tr key={h.ip}>
                        <td className="mono">{h.ip}</td>
                        <td className="small">{h.hostname}</td>
                        <td className="small muted">{h.os}</td>
                        <td className="mono">{h.open.length}</td>
                        <td>
                          <span className={`pill ${h.status === 'up' ? 'pill-ok' : 'pill-muted'}`}><span className="pd" />{h.status}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <Panel title="Scanner Console" sub="Live output">
            <div className="feed">
              {log.length === 0 ? (
                <div className="muted small">Idle. Awaiting scan.</div>
              ) : (
                log.map((l, i) => (
                  <div className="ln" key={i}><span className="msg text-mono">{l}</span></div>
                ))
              )}
              {scanning && <div className="ln"><span className="msg blink text-mono">_</span></div>}
            </div>
          </Panel>
        </div>

        {phase === 'done' && found.some((h) => h.open.length > 0) && (
          <Panel title="Service Detail" sub="Open ports per discovered host" className="mt-24">
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>State</th><th>Version</th></tr></thead>
                <tbody>
                  {found.flatMap((h) =>
                    h.open.map((p) => (
                      <tr key={`${h.ip}:${p.port}`}>
                        <td className="mono small">{h.ip}</td>
                        <td className="mono">{p.port}</td>
                        <td>{p.service}</td>
                        <td><span className={`pill ${p.state === 'open' ? 'pill-ok' : 'pill-muted'}`}><span className="pd" />{p.state}</span></td>
                        <td className="small muted">{p.version}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </Panel>
        )}
      </div>
    </>
  )
}
