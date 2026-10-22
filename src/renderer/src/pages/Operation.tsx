import React, { useCallback, useEffect, useState } from 'react'
import TopBar from '../components/TopBar'
import { Panel, Disclaimer, Stat } from '../components/ui'
import { IconCheck, IconLock, IconRefresh } from '../components/icons'
import { useSettings } from '../store/store'
import { TECHNIQUES, Roe, Technique } from '../../../shared/roe'
import type { AuditEntry, ChainCheck } from '../../../shared/audit'

const hasBridge = typeof window !== 'undefined' && !!window.ruy?.roe

const emptyRoe = (operator: string): Roe => ({
  operation: '',
  operator,
  allow: { scan: true, proxy: true, repeater: true, discovery: true, active: true, retest: true, intruder: false }
})

const resultPill = (r: AuditEntry['result']): string => (r === 'allowed' ? 'pill-ok' : r === 'blocked' ? 'pill-crit' : 'pill-muted')

export default function Operation() {
  const [settings] = useSettings()
  const [active, setActive] = useState<Roe | null>(null)
  const [form, setForm] = useState<Roe>(() => emptyRoe(settings.operatorName))
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [check, setCheck] = useState<(ChainCheck & { file: string }) | null>(null)
  const [note, setNote] = useState<string | null>(null)
  const [pkgNote, setPkgNote] = useState<{ ok: boolean; lines: string[] } | null>(null)

  const refresh = useCallback(async () => {
    if (!hasBridge) return
    setEntries(await window.ruy.audit.list(200))
  }, [])

  useEffect(() => {
    if (!hasBridge) return
    void window.ruy.roe.get().then((r) => {
      setActive(r)
      if (r) setForm(r)
    })
    void refresh()
  }, [refresh])

  const save = async () => {
    const res = await window.ruy.roe.set(form)
    if (!res.ok || !res.roe) { setNote(res.error || 'Gagal menyimpan RoE.'); return }
    setActive(res.roe)
    setForm(res.roe)
    setCheck(null)
    setNote(`RoE "${res.roe.operation}" aktif.`)
    await refresh()
  }

  const verify = async () => {
    setCheck(await window.ruy.audit.verify())
    await refresh()
  }

  const exportPkg = async () => {
    const r = await window.ruy.evidence.export()
    setPkgNote(r.ok
      ? { ok: true, lines: [`Exported ${r.count} evidence file(s) to:`, r.dir || '', `Fingerprint (sha256 manifest.json): ${r.fingerprint}`] }
      : { ok: false, lines: [r.error || 'Export failed.'] })
    await refresh()
  }

  const verifyPkg = async () => {
    const r = await window.ruy.evidence.verify()
    if ('cancelled' in r) return
    const extra = r.unlisted.length ? [`File tidak tercantum di manifest: ${r.unlisted.join(', ')}`] : []
    setPkgNote(r.ok && r.unlisted.length === 0
      ? { ok: true, lines: [
          `✅ Paket utuh — ${r.count} file bukti + audit log cocok.`,
          r.dir,
          `Fingerprint: ${r.fingerprint}`,
          r.exportedHere ? 'Fingerprint tercatat di audit log operasi aktif (diekspor dari sini).' : 'Fingerprint tidak ada di log operasi aktif — cocokkan dengan nilai dari operator pengekspor.'
        ] }
      : { ok: false, lines: ['❌ Paket TIDAK utuh:', ...(r.ok ? [] : r.problems), ...extra, r.dir] })
    await refresh()
  }

  const toggle = (t: Technique) => setForm((f) => ({ ...f, allow: { ...f.allow, [t]: !f.allow[t] } }))
  const blocked = entries.filter((e) => e.result === 'blocked').length

  return (
    <>
      <TopBar title="Operation" sub="Rules of Engagement & tamper-evident audit log" />
      <div className="content page">
        <Disclaimer>
          Every scan, proxied request and active probe must fit the <strong>Rules of Engagement</strong> below: the
          authorized operation, operator, time window and permitted techniques. Without an active RoE, all traffic is
          blocked. Every decision (allowed or blocked) is written to a <strong>SHA-256 hash-chained audit log</strong>;
          editing any line breaks the chain.
        </Disclaimer>
        {!hasBridge && <div className="small muted mt-16">Bridge tidak tersedia — jalankan sebagai aplikasi desktop.</div>}

        <div className="grid grid-4 mt-16">
          <Stat label="Operation" value={active?.operation || '—'} icon={<IconLock />} meta={active ? active.operator : 'no RoE'} />
          <Stat label="Audit entries" value={entries.length} meta="latest 200" />
          <Stat label="Blocked" value={blocked} meta="out of RoE / scope" />
          <Stat label="Chain" value={check ? (check.ok ? 'Intact' : 'Broken') : '—'} meta={check ? (check.ok ? `${check.count} entries` : `line ${check.brokenAt}`) : 'not verified'} />
        </div>

        <div className="grid grid-2 mt-24" style={{ alignItems: 'start' }}>
          <Panel title="Rules of Engagement" sub="Saved in the main process; changes are audited">
            <div style={{ display: 'grid', gap: 14 }}>
              <label className="field">
                <span className="lab">Operation name</span>
                <input type="text" value={form.operation} placeholder="OP-KARTIKA-01" onChange={(e) => setForm({ ...form, operation: e.target.value })} />
              </label>
              <label className="field">
                <span className="lab">Operator</span>
                <input type="text" value={form.operator} onChange={(e) => setForm({ ...form, operator: e.target.value })} />
              </label>
              <div className="grid grid-2">
                <label className="field">
                  <span className="lab">Window start</span>
                  <input type="datetime-local" value={form.windowStart || ''} onChange={(e) => setForm({ ...form, windowStart: e.target.value || undefined })} />
                </label>
                <label className="field">
                  <span className="lab">Window end</span>
                  <input type="datetime-local" value={form.windowEnd || ''} onChange={(e) => setForm({ ...form, windowEnd: e.target.value || undefined })} />
                </label>
              </div>
              <div>
                <div className="small muted" style={{ marginBottom: 8 }}>Permitted techniques</div>
                {TECHNIQUES.map((t) => (
                  <div key={t.id} className="flex gap-12" style={{ alignItems: 'center', padding: '6px 0' }}>
                    <label className="switch">
                      <input type="checkbox" checked={!!form.allow[t.id]} onChange={() => toggle(t.id)} />
                      <span className="track" />
                    </label>
                    <span>{t.label}</span>
                    <span className="mono small muted">{t.id}</span>
                  </div>
                ))}
              </div>
              <div className="flex gap-12" style={{ alignItems: 'center' }}>
                <button className="btn btn-primary" onClick={save} disabled={!hasBridge}><IconCheck size={14} />Activate RoE</button>
                {note && <span className="small muted">{note}</span>}
              </div>
            </div>
          </Panel>

          <Panel
            title="Audit log"
            sub={active ? `Operation ${active.operation}` : 'Entries before any RoE go to _no-operation'}
            right={
              <div className="flex gap-8">
                <button className="btn btn-ghost btn-sm" onClick={refresh} disabled={!hasBridge}><IconRefresh size={14} />Refresh</button>
                <button className="btn btn-primary btn-sm" onClick={verify} disabled={!hasBridge}><IconLock size={14} />Verify integrity</button>
              </div>
            }
          >
            {check && (
              <div className={`pill ${check.ok ? 'pill-ok' : 'pill-crit'}`} style={{ marginBottom: 12 }}>
                {check.ok
                  ? `✅ Chain intact — ${check.count} entries, head ${check.head.slice(0, 12)}…`
                  : `❌ Log tampered at line ${check.brokenAt}: ${check.reason}`}
              </div>
            )}
            {check && <div className="mono small muted" style={{ marginBottom: 12, wordBreak: 'break-all' }}>{check.file}</div>}
            <div className="table-wrap" style={{ maxHeight: 520, overflow: 'auto' }}>
              <table className="data">
                <thead><tr><th>#</th><th>Time</th><th>Action</th><th>Target</th><th>Result</th></tr></thead>
                <tbody>
                  {[...entries].reverse().map((e) => (
                    <tr key={e.seq}>
                      <td className="mono small">{e.seq}</td>
                      <td className="mono small">{new Date(e.at).toLocaleTimeString('en-GB', { hour12: false })}</td>
                      <td className="mono small">{e.action}</td>
                      <td className="mono small" style={{ maxWidth: 260, wordBreak: 'break-all' }} title={e.detail}>{e.target}{e.detail && <div className="muted">{e.detail}</div>}</td>
                      <td><span className={`pill ${resultPill(e.result)}`}><span className="pd" />{e.result}</span></td>
                    </tr>
                  ))}
                  {entries.length === 0 && <tr><td colSpan={5}><div className="empty">No audit entries yet.</div></td></tr>}
                </tbody>
              </table>
            </div>
          </Panel>
        </div>

        <Panel
          title="Evidence package"
          sub="Confirmed findings are saved to disk with their raw request/response; export them with a SHA-256 manifest"
          className="mt-24"
          right={
            <div className="flex gap-8">
              <button className="btn btn-primary btn-sm" onClick={exportPkg} disabled={!hasBridge}>Export evidence</button>
              <button className="btn btn-ghost btn-sm" onClick={verifyPkg} disabled={!hasBridge}>Verify package…</button>
            </div>
          }
        >
          {pkgNote ? (
            <div className={`pill ${pkgNote.ok ? 'pill-ok' : 'pill-crit'}`} style={{ display: 'block', whiteSpace: 'normal', borderRadius: 8, padding: 12 }}>
              {pkgNote.lines.map((l, i) => <div key={i} className={i === 0 ? '' : 'mono small'} style={{ wordBreak: 'break-all' }}>{l}</div>)}
            </div>
          ) : (
            <div className="small muted">
              Export copies the evidence files and the audit log of the active operation into Downloads. A recipient can
              verify the folder here: any changed byte, missing file or edited audit line is reported. Compare the
              fingerprint with the <span className="mono">evidence:export</span> entry in this audit log.
            </div>
          )}
        </Panel>
      </div>
    </>
  )
}
