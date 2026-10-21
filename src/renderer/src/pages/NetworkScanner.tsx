import React, { useEffect, useRef, useState } from 'react'
import TopBar from '../components/TopBar'
import { Panel, Disclaimer, Meter } from '../components/ui'
import { IconPlay, IconStop, IconScan } from '../components/icons'
import ScopeBar from '../components/ScopeBar'
import { MOCK_HOSTS, HostResult, severityPill, Severity } from '../data/mock'
import { usePersistentState, useSettings } from '../store/store'
import { profilePorts, ScanHost, ScanEvent, ScanProfile, ScanSummary } from '../../../shared/scan'
import { analyzeScan } from '../../../shared/rules'
import { addFindings } from '../store/findings'

type Phase = 'idle' | 'scanning' | 'done'
type Mode = 'live' | 'sim'

// Unified row shape so the live engine and the simulation share one table.
interface DisplayHost {
  ip: string
  hostname: string
  os: string
  status: string
  open: { port: number; service: string; state: string; version: string }[]
  risk?: Severity
}

const simToDisplay = (h: HostResult): DisplayHost => ({
  ip: h.ip,
  hostname: h.hostname,
  os: h.os,
  status: h.status,
  open: h.openPorts.map((p) => ({ port: p.port, service: p.service, state: p.state, version: p.version })),
  risk: h.risk
})

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
  const [mode, setMode] = usePersistentState<Mode>('scanner.mode', hasBridge ? 'live' : 'sim')
  const [target, setTarget] = usePersistentState('scanner.target', '127.0.0.1')
  const [profile, setProfile] = usePersistentState<ScanProfile>('scanner.profile', 'quick')
  const [phase, setPhase] = useState<Phase>('idle')
  const [progress, setProgress] = useState(0)
  const [found, setFound] = useState<DisplayHost[]>([])
  const [log, setLog] = useState<string[]>([])
  const [note, setNote] = useState<string | null>(null)
  const [summary, setSummary] = useState<ScanSummary | null>(null)

  const timer = useRef<number | null>(null)
  const scanIdRef = useRef<number>(0)
  const runRef = useRef(0)
  const offProgress = useRef<(() => void) | null>(null)

  const effMode: Mode = hasBridge ? mode : 'sim'

  const clearTimer = () => {
    if (timer.current) window.clearInterval(timer.current)
    timer.current = null
  }

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

  // On leave: stop the sim timer and cancel any live scan still running in main.
  useEffect(() => () => {
    clearTimer()
    if (scanIdRef.current) void window.ruy?.scan?.cancel(scanIdRef.current)
    scanIdRef.current = 0
  }, [])

  const stopSim = () => { clearTimer(); setPhase('done') }

  const startSim = () => {
    runRef.current++
    clearTimer()
    setNote(null)
    setSummary(null)
    setPhase('scanning')
    setProgress(0)
    setFound([])
    setLog([`> initiating ${profile} sweep of ${target} (SIMULATED)`, '> no packets are sent on the real network'])
    let step = 0
    const totalSteps = 36
    timer.current = window.setInterval(() => {
      step += 1
      setProgress(Math.round((step / totalSteps) * 100))
      if (step % 6 === 0) {
        const host = MOCK_HOSTS[step / 6 - 1]
        if (host) {
          setFound((f) => [...f, simToDisplay(host)])
          setLog((l) => [...l, `> host up  ${host.ip.padEnd(13)} ${host.hostname}  [${host.openPorts.length} open]`])
        }
      }
      if (step >= totalSteps) {
        clearTimer()
        setProgress(100)
        setPhase('done')
        setLog((l) => [...l, `> sweep complete — ${MOCK_HOSTS.length} hosts enumerated`])
      }
    }, 140)
  }

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
      const res = await window.ruy.scan.run({ target, profile }, settings.scope, id)
      // A newer scan (live or sim) started meanwhile: don't let this result overwrite it.
      if (runRef.current !== run) return
      if (!res.ok) {
        setNote(res.blocked ? `⛔ ${res.error}` : `⚠️ ${res.error}`)
        setLog((l) => [...l, `> ${res.error}`])
        setPhase('idle')
        setProgress(0)
        return
      }
      // The resolved result is authoritative (covers hosts that streamed late).
      if (res.hosts) setFound(res.hosts.map(liveToDisplay))
      if (res.summary) setSummary(res.summary)
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

  const start = () => (effMode === 'live' ? void startLive() : startSim())

  const stop = () => {
    if (effMode === 'live') {
      if (window.ruy?.scan && scanIdRef.current) window.ruy.scan.cancel(scanIdRef.current)
      scanIdRef.current = 0
      setPhase('done')
    } else {
      stopSim()
    }
  }

  const portCount = profilePorts(profile).length
  const scanning = phase === 'scanning'

  return (
    <>
      <TopBar title="Network Scanner" sub={effMode === 'live' ? 'Real TCP connect scan (scope-gated)' : 'Simulated host & service discovery'} />
      <div className="content page">
        {effMode === 'live' ? (
          <Disclaimer>
            <strong>Live mode opens real TCP connections.</strong> Only targets inside your Authorized scope are
            scanned — add the host or subnet (e.g. <span className="mono">10.20.0.0/24</span>) below. Use this only
            against systems you own or are authorized to test.
          </Disclaimer>
        ) : (
          <Disclaimer>
            This module <strong>simulates</strong> a network sweep against a fabricated lab range. It never emits
            real traffic, probes real hosts, or touches your network interfaces. Results are fixed demo data.
          </Disclaimer>
        )}

        {effMode === 'live' && <div className="mt-16"><ScopeBar /></div>}

        <Panel title="Scan Configuration" className="mt-16">
          <div className="grid grid-3" style={{ alignItems: 'end' }}>
            <label className="field">
              <span className="lab">Target {effMode === 'live' ? '(IP / CIDR / range)' : 'Range'}</span>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={scanning}
                placeholder={effMode === 'live' ? '127.0.0.1  /  10.20.0.0/24  /  10.0.0.1-50' : '10.20.0.0/24'}
              />
            </label>
            <label className="field">
              <span className="lab">Profile{effMode === 'live' ? ` — ${portCount} ports` : ''}</span>
              <select value={profile} onChange={(e) => setProfile(e.target.value as ScanProfile)} disabled={scanning}>
                <option value="quick">Quick (top 100 ports)</option>
                <option value="standard">Standard (common ports)</option>
                <option value="deep">Deep (common ports + version)</option>
              </select>
            </label>
            <div className="flex gap-12">
              {!scanning ? (
                <button className="btn btn-primary" onClick={start}><IconPlay />Run Scan</button>
              ) : (
                <button className="btn btn-danger" onClick={stop}><IconStop />Stop</button>
              )}
            </div>
          </div>

          {hasBridge && (
            <div className="flex gap-12 mt-16" style={{ alignItems: 'center' }}>
              <span className="small muted">Mode:</span>
              <div className="theme-toggle">
                <button className={effMode === 'sim' ? 'on' : ''} onClick={() => !scanning && setMode('sim')} disabled={scanning}>Simulation</button>
                <button className={effMode === 'live' ? 'on' : ''} onClick={() => !scanning && setMode('live')} disabled={scanning}>Live</button>
              </div>
            </div>
          )}

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
                  <thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Open</th><th>{effMode === 'live' ? 'State' : 'Risk'}</th></tr></thead>
                  <tbody>
                    {found.map((h) => (
                      <tr key={h.ip}>
                        <td className="mono">{h.ip}</td>
                        <td className="small">{h.hostname}</td>
                        <td className="small muted">{h.os}</td>
                        <td className="mono">{h.open.length}</td>
                        <td>
                          {h.risk ? (
                            <span className={`pill ${severityPill[h.risk]}`}><span className="pd" />{h.risk}</span>
                          ) : (
                            <span className={`pill ${h.status === 'up' ? 'pill-ok' : 'pill-muted'}`}><span className="pd" />{h.status}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <Panel title="Scanner Console" sub={effMode === 'live' ? 'Live output' : 'Simulated output'}>
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
