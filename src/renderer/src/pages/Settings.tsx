import React, { useState } from 'react'
import TopBar from '../components/TopBar'
import { Panel, Disclaimer } from '../components/ui'
import { IconTrash, IconCheck, IconCpu } from '../components/icons'
import { useSettings, resetDemoEnvironment } from '../store/store'

function Row({ title, desc, children }: { title: string; desc: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between" style={{ padding: '14px 0', borderBottom: '1px solid var(--line-soft)' }}>
      <div style={{ maxWidth: 520 }}>
        <div style={{ color: 'var(--white)', fontWeight: 600, fontSize: 13.5 }}>{title}</div>
        <div className="small muted" style={{ marginTop: 3 }}>{desc}</div>
      </div>
      {children}
    </div>
  )
}

export default function Settings() {
  const [settings, patch] = useSettings()
  const [confirming, setConfirming] = useState(false)
  const [saved, setSaved] = useState(false)

  const versions = typeof window !== 'undefined' && window.ruy ? window.ruy.versions : { electron: '—', chrome: '—', node: '—' }
  const platform = typeof window !== 'undefined' && window.ruy ? window.ruy.platform : '—'

  const doReset = () => {
    resetDemoEnvironment()
    // Reload so every module re-reads pristine defaults.
    window.location.reload()
  }

  const flash = () => { setSaved(true); window.setTimeout(() => setSaved(false), 1400) }

  return (
    <>
      <TopBar title="Settings" sub="Local preferences & stored data" />
      <div className="content page">
        <div className="grid grid-2 mt-16" style={{ alignItems: 'start' }}>
          <Panel title="Preferences" sub="Stored locally on this machine">
            <Row title="Operator name" desc="Shown on generated reports.">
              <input
                type="text"
                value={settings.operatorName}
                onChange={(e) => patch({ operatorName: e.target.value })}
                onBlur={flash}
                style={{ width: 200 }}
              />
            </Row>
            <Row title="Color theme" desc="Switch between the Dark Kingdom and Silver Daylight themes (also in the top-right).">
              <div className="theme-toggle">
                <button className={settings.theme === 'light' ? 'on' : ''} onClick={() => patch({ theme: 'light' })}>Light</button>
                <button className={settings.theme === 'dark' ? 'on' : ''} onClick={() => patch({ theme: 'dark' })}>Dark</button>
              </div>
            </Row>
            <Row title="Local persistence" desc="Remember findings, scope and settings across restarts.">
              <label className="switch">
                <input type="checkbox" checked={settings.persistence} onChange={(e) => patch({ persistence: e.target.checked })} />
                <span className="track" />
              </label>
            </Row>
            <Row title="Reduce motion" desc="Minimize page transitions and animated indicators.">
              <label className="switch">
                <input type="checkbox" checked={settings.reduceMotion} onChange={(e) => patch({ reduceMotion: e.target.checked })} />
                <span className="track" />
              </label>
            </Row>
            {saved && <div className="pill pill-ok mt-16"><IconCheck size={12} />Preferences saved</div>}
          </Panel>

          <div style={{ display: 'grid', gap: 18 }}>
            <Panel title="Local data">
              <Disclaimer>
                Resetting clears everything stored locally (scope, scan settings, findings, preferences) and
                restores the application to its default state.
              </Disclaimer>
              <div className="mt-16">
                {!confirming ? (
                  <button className="btn btn-danger" onClick={() => setConfirming(true)}><IconTrash />Reset local data</button>
                ) : (
                  <div className="flex gap-12 items-center wrap">
                    <span className="small">This cannot be undone. Continue?</span>
                    <button className="btn btn-danger" onClick={doReset}>Yes, reset everything</button>
                    <button className="btn btn-ghost" onClick={() => setConfirming(false)}>Cancel</button>
                  </div>
                )}
              </div>
            </Panel>

            <Panel title="About" sub="Build information" right={<IconCpu />}>
              <div className="table-wrap">
                <table className="data">
                  <tbody>
                    <tr><td className="muted small">Application</td><td>Interu — Cyber Operations</td></tr>
                    <tr><td className="muted small">Team</td><td>RUY Cybersecurity Team</td></tr>
                    <tr><td className="muted small">Version</td><td className="mono">1.0.0</td></tr>
                    <tr><td className="muted small">Runtime</td><td className="mono">Electron {versions.electron}</td></tr>
                    <tr><td className="muted small">Chromium</td><td className="mono">{versions.chrome}</td></tr>
                    <tr><td className="muted small">Node</td><td className="mono">{versions.node}</td></tr>
                    <tr><td className="muted small">Platform</td><td className="mono">{platform}</td></tr>
                  </tbody>
                </table>
              </div>
            </Panel>
          </div>
        </div>
      </div>
    </>
  )
}
