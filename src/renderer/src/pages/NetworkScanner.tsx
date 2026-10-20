import React, { useEffect, useRef, useState } from 'react'
import TopBar from '../components/TopBar'
import { Panel, Disclaimer, Meter } from '../components/ui'
import { IconPlay, IconStop, IconScan } from '../components/icons'
import { MOCK_HOSTS, HostResult, severityPill } from '../data/mock'
import { usePersistentState } from '../store/store'

type Phase = 'idle' | 'scanning' | 'done'

export default function NetworkScanner() {
  const [target, setTarget] = usePersistentState('scanner.target', '10.20.0.0/24')
  const [profile, setProfile] = usePersistentState('scanner.profile', 'standard')
  const [phase, setPhase] = useState<Phase>('idle')
  const [progress, setProgress] = useState(0)
  const [found, setFound] = useState<HostResult[]>([])
  const [log, setLog] = useState<string[]>([])
  const timer = useRef<number | null>(null)

  const stop = () => {
    if (timer.current) window.clearInterval(timer.current)
    timer.current = null
  }

  useEffect(() => () => stop(), [])

  const start = () => {
    stop()
    setPhase('scanning')
    setProgress(0)
    setFound([])
    setLog([`> initiating ${profile} sweep of ${target} (SIMULATED)`, '> no packets are sent on the real network'])
    let step = 0
    const totalSteps = 36
    timer.current = window.setInterval(() => {
      step += 1
      setProgress(Math.round((step / totalSteps) * 100))
      // Reveal a host roughly every 6 steps.
      if (step % 6 === 0) {
        const idx = step / 6 - 1
        const host = MOCK_HOSTS[idx]
        if (host) {
          setFound((f) => [...f, host])
          setLog((l) => [...l, `> host up  ${host.ip.padEnd(13)} ${host.hostname}  [${host.openPorts.length} open]`])
        }
      }
      if (step >= totalSteps) {
        stop()
        setProgress(100)
        setPhase('done')
        setLog((l) => [...l, `> sweep complete — ${MOCK_HOSTS.length} hosts enumerated`])
      }
    }, 140)
  }

  return (
    <>
      <TopBar title="Network Scanner" sub="Simulated host & service discovery" />
      <div className="content page">
        <Disclaimer>
          This module <strong>simulates</strong> a network sweep against a fabricated lab range. It never emits
          real traffic, probes real hosts, or touches your network interfaces. Results are fixed demo data.
        </Disclaimer>

        <Panel title="Scan Configuration" className="mt-16">
          <div className="grid grid-3" style={{ alignItems: 'end' }}>
            <label className="field">
              <span className="lab">Target Range</span>
              <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} disabled={phase === 'scanning'} />
            </label>
            <label className="field">
              <span className="lab">Profile</span>
              <select value={profile} onChange={(e) => setProfile(e.target.value)} disabled={phase === 'scanning'}>
                <option value="quick">Quick (top 100 ports)</option>
                <option value="standard">Standard (1000 ports)</option>
                <option value="deep">Deep (full + version)</option>
              </select>
            </label>
            <div className="flex gap-12">
              {phase !== 'scanning' ? (
                <button className="btn btn-primary" onClick={start}><IconPlay />Run Scan</button>
              ) : (
                <button className="btn btn-danger" onClick={() => { stop(); setPhase('done') }}><IconStop />Stop</button>
              )}
            </div>
          </div>

          {phase !== 'idle' && (
            <div className="mt-24">
              <div className="flex justify-between small muted" style={{ marginBottom: 6 }}>
                <span>{phase === 'scanning' ? 'Sweeping…' : 'Complete'}</span>
                <span className="mono">{progress}%</span>
              </div>
              <Meter value={progress} tone={phase === 'done' ? 'ok' : undefined} />
            </div>
          )}
        </Panel>

        <div className="grid grid-2 mt-24">
          <Panel title="Discovered Hosts" sub={`${found.length} enumerated`} right={<IconScan />}>
            {found.length === 0 ? (
              <div className="empty">No hosts yet. Run a scan to populate simulated results.</div>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Ports</th><th>Risk</th></tr></thead>
                  <tbody>
                    {found.map((h) => (
                      <tr key={h.ip}>
                        <td className="mono">{h.ip}</td>
                        <td className="small">{h.hostname}</td>
                        <td className="small muted">{h.os}</td>
                        <td className="mono">{h.openPorts.length}</td>
                        <td><span className={`pill ${severityPill[h.risk]}`}><span className="pd" />{h.risk}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <Panel title="Scanner Console" sub="Simulated output">
            <div className="feed">
              {log.length === 0 ? (
                <div className="muted small">Idle. Awaiting scan.</div>
              ) : (
                log.map((l, i) => (
                  <div className="ln" key={i}><span className="msg text-mono">{l}</span></div>
                ))
              )}
              {phase === 'scanning' && <div className="ln"><span className="msg blink text-mono">_</span></div>}
            </div>
          </Panel>
        </div>

        {phase === 'done' && (
          <Panel title="Service Detail" sub="Open ports per discovered host" className="mt-24">
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>State</th><th>Version</th></tr></thead>
                <tbody>
                  {found.flatMap((h) =>
                    h.openPorts.map((p) => (
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
