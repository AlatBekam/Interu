import React, { useState } from 'react'
import TopBar from '../components/TopBar'
import { Panel, Stat, Disclaimer } from '../components/ui'
import { IconFirewall, IconPlus, IconTrash, IconLock } from '../components/icons'
import { DEFAULT_FIREWALL_RULES, FirewallRule } from '../data/mock'
import { usePersistentState } from '../store/store'

const blank = (): FirewallRule => ({
  id: `fw-${Date.now()}`,
  name: '',
  direction: 'inbound',
  protocol: 'TCP',
  port: '',
  source: 'any',
  action: 'deny',
  enabled: true
})

export default function Firewall() {
  const [rules, setRules] = usePersistentState<FirewallRule[]>('firewall.rules', DEFAULT_FIREWALL_RULES)
  const [draft, setDraft] = useState<FirewallRule>(blank())
  const [adding, setAdding] = useState(false)

  const toggle = (id: string) =>
    setRules((rs) => rs.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)))

  const remove = (id: string) => setRules((rs) => rs.filter((r) => r.id !== id))

  const add = () => {
    if (!draft.name.trim() || !draft.port.trim()) return
    setRules((rs) => [{ ...draft, id: `fw-${Date.now()}` }, ...rs])
    setDraft(blank())
    setAdding(false)
  }

  const active = rules.filter((r) => r.enabled).length
  const denies = rules.filter((r) => r.enabled && r.action === 'deny').length

  return (
    <>
      <TopBar title="Firewall Rules" sub="Simulated policy editor" />
      <div className="content page">
        <Disclaimer>
          This is a <strong>mock policy editor</strong>. Rules are stored locally and have no effect on the
          Windows Firewall or any real network device. Nothing here changes your system configuration.
        </Disclaimer>

        <div className="grid grid-4 mt-16">
          <Stat label="Total Rules" value={rules.length} icon={<IconFirewall />} />
          <Stat label="Active" value={active} meta="enabled" />
          <Stat label="Deny Rules" value={denies} meta="blocking" icon={<IconLock />} />
          <Stat label="Custom Rules" value={rules.filter((r) => !r.builtin).length} meta="user-created" />
        </div>

        <Panel
          title="Policy"
          sub="Evaluated top to bottom"
          className="mt-24"
          right={<button className="btn btn-primary btn-sm" onClick={() => setAdding((a) => !a)}><IconPlus />New Rule</button>}
        >
          {adding && (
            <div className="grid grid-3 mb-24" style={{ alignItems: 'end', gap: 12 }}>
              <label className="field"><span className="lab">Rule Name</span>
                <input type="text" placeholder="e.g. Block Tor exit nodes" value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} /></label>
              <label className="field"><span className="lab">Direction</span>
                <select value={draft.direction} onChange={(e) => setDraft({ ...draft, direction: e.target.value as FirewallRule['direction'] })}>
                  <option value="inbound">inbound</option><option value="outbound">outbound</option></select></label>
              <label className="field"><span className="lab">Protocol</span>
                <select value={draft.protocol} onChange={(e) => setDraft({ ...draft, protocol: e.target.value as FirewallRule['protocol'] })}>
                  <option>TCP</option><option>UDP</option><option>ICMP</option><option>ANY</option></select></label>
              <label className="field"><span className="lab">Port</span>
                <input type="text" placeholder="443 or *" value={draft.port} onChange={(e) => setDraft({ ...draft, port: e.target.value })} /></label>
              <label className="field"><span className="lab">Source</span>
                <input type="text" placeholder="any / CIDR" value={draft.source} onChange={(e) => setDraft({ ...draft, source: e.target.value })} /></label>
              <label className="field"><span className="lab">Action</span>
                <select value={draft.action} onChange={(e) => setDraft({ ...draft, action: e.target.value as FirewallRule['action'] })}>
                  <option value="deny">deny</option><option value="allow">allow</option></select></label>
              <div className="flex gap-12" style={{ gridColumn: '1 / -1' }}>
                <button className="btn btn-primary" onClick={add} disabled={!draft.name.trim() || !draft.port.trim()}><IconPlus />Add Rule</button>
                <button className="btn btn-ghost" onClick={() => { setAdding(false); setDraft(blank()) }}>Cancel</button>
              </div>
            </div>
          )}

          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr><th>Enabled</th><th>Name</th><th>Dir</th><th>Proto</th><th>Port</th><th>Source</th><th>Action</th><th></th></tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id} style={{ opacity: r.enabled ? 1 : 0.5 }}>
                    <td>
                      <label className="switch">
                        <input type="checkbox" checked={r.enabled} onChange={() => toggle(r.id)} />
                        <span className="track" />
                      </label>
                    </td>
                    <td>{r.name}{r.builtin && <span className="pill pill-muted" style={{ marginLeft: 8 }}><span className="pd" />default</span>}</td>
                    <td className="small">{r.direction}</td>
                    <td className="mono small">{r.protocol}</td>
                    <td className="mono">{r.port}</td>
                    <td className="mono small">{r.source}</td>
                    <td><span className={`pill ${r.action === 'deny' ? 'pill-crit' : 'pill-ok'}`}><span className="pd" />{r.action}</span></td>
                    <td style={{ textAlign: 'right' }}>
                      {!r.builtin && (
                        <button className="btn btn-ghost btn-sm" onClick={() => remove(r.id)} title="Delete rule"><IconTrash size={14} /></button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </>
  )
}
