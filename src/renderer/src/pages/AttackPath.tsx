import React, { useMemo, useState } from 'react'
import TopBar from '../components/TopBar'
import { Panel, Disclaimer, Stat } from '../components/ui'
import { IconTarget } from '../components/icons'
import { severityPill, Severity } from '../data/mock'
import { useFindings } from '../store/findings'
import { buildAttackGraph, GraphNode } from '../../../shared/attackPath'
import type { RuleSeverity } from '../../../shared/rules'
import { latestRetest } from '../../../shared/retest'

const SEV_COLOR: Record<RuleSeverity, string> = {
  critical: 'var(--crit)', high: '#e08f56', medium: 'var(--warn)', low: 'var(--info)', info: 'var(--silver-500)'
}

const COL = { host: { x: 8, w: 190 }, service: { x: 250, w: 110 }, finding: { x: 410, w: 540 } }
const ROW = 38
const NODE_H = 26
const clip = (s: string, n: number): string => (s.length > n ? s.slice(0, n - 1) + '…' : s)

export default function AttackPath() {
  const findings = useFindings()
  const graph = useMemo(() => buildAttackGraph(findings), [findings])
  const [selected, setSelected] = useState<string | null>(null)

  // One row per finding, grouped by host then service; parents sit at the middle of their children.
  // `top` holds each node's top edge.
  const layout = useMemo(() => {
    const byId = new Map(graph.nodes.map((n) => [n.id, n]))
    const parentOf = new Map(graph.edges.map((e) => [e.to, e.from]))
    const leaves = graph.nodes
      .filter((n) => n.kind === 'finding')
      .sort((a, b) => a.host.localeCompare(b.host) || (parentOf.get(a.id) || '').localeCompare(parentOf.get(b.id) || '') || (a.tactic?.order ?? 0) - (b.tactic?.order ?? 0))
    const top = new Map<string, number>()
    leaves.forEach((n, i) => top.set(n.id, 12 + i * ROW))
    for (const kind of ['service', 'host'] as const) {
      for (const n of graph.nodes.filter((x) => x.kind === kind)) {
        const kids = graph.edges.filter((e) => e.from === n.id).map((e) => top.get(e.to)).filter((v): v is number => v != null)
        if (kids.length) top.set(n.id, (Math.min(...kids) + Math.max(...kids)) / 2)
      }
    }
    return { byId, top, height: Math.max(80, 24 + leaves.length * ROW) }
  }, [graph])

  const critical = new Set(graph.critical)
  const sel = selected ? layout.byId.get(selected) : undefined
  const hosts = graph.nodes.filter((n) => n.kind === 'host').length
  const worst = graph.critical.length ? layout.byId.get(graph.critical[graph.critical.length - 1]) : undefined

  const box = (n: GraphNode) => {
    const c = COL[n.kind]
    const top = layout.top.get(n.id) ?? 0
    const f = n.finding
    const stroke = f ? SEV_COLOR[f.severity] : critical.has(n.id) ? 'var(--crit)' : 'var(--line-strong)'
    const text = n.kind === 'finding' && n.tactic ? `[${n.tactic.name}] ${n.label}` : n.label
    const select = () => setSelected(n.kind === 'finding' ? n.id : null)
    return (
      <g
        key={n.id}
        role={n.kind === 'finding' ? 'button' : undefined}
        tabIndex={n.kind === 'finding' ? 0 : undefined}
        aria-label={n.kind === 'finding' ? `${f?.severity} ${text}` : text}
        onClick={select}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') select() }}
        style={{ cursor: n.kind === 'finding' ? 'pointer' : 'default' }}
      >
        <rect
          x={c.x} y={top} width={c.w} height={NODE_H} rx={6}
          fill={selected === n.id ? 'var(--panel-600)' : 'var(--panel-800)'}
          stroke={stroke} strokeWidth={critical.has(n.id) ? 2.2 : 1}
          strokeDasharray={f && f.confidence === 'suspected' ? '4 3' : undefined}
        />
        <text x={c.x + 10} y={top + 17} fontSize={12} fill="var(--silver-100)" fontFamily={n.kind === 'finding' ? 'var(--font-ui)' : 'var(--font-mono)'}>
          {clip(text, n.kind === 'finding' ? 70 : n.kind === 'host' ? 24 : 14)}
        </text>
      </g>
    )
  }

  return (
    <>
      <TopBar title="Attack Path" sub="Correlated view: host → service → finding, by MITRE ATT&CK tactic" />
      <div className="content page">
        <Disclaimer>
          Every finding from the Network Scanner, Proxy and Rule Engine is placed on its host and service. The
          <strong> critical path</strong> (red) leads to the most severe <em>confirmed</em> finding. Dashed boxes are
          <em> suspected</em>. Tactics come from the template's ATT&CK technique when present, otherwise from a heuristic
          (exposed service = Discovery, web weakness = Initial Access, leaked secret = Credential Access).
        </Disclaimer>

        <div className="grid grid-4 mt-16">
          <Stat label="Hosts" value={hosts} icon={<IconTarget />} />
          <Stat label="Findings" value={findings.length} />
          <Stat label="Critical path" value={graph.critical.length ? `${graph.critical.length} steps` : '—'} meta={worst ? clip(worst.label, 28) : 'nothing confirmed'} />
          <Stat label="Worst confirmed" value={worst?.finding?.severity || '—'} meta={worst?.host || ''} />
        </div>

        <Panel title="Graph" sub="Click a finding for details" className="mt-24">
          {findings.length === 0 ? (
            <div className="empty">No findings yet. Run a scan, browse via the Proxy, or run active checks in the Rule Engine.</div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <svg viewBox={`0 0 960 ${layout.height}`} width="100%" style={{ minWidth: 720, display: 'block' }} role="img" aria-label="Attack path graph">
                {graph.edges.map((e) => {
                  const a = layout.byId.get(e.from)
                  const b = layout.byId.get(e.to)
                  if (!a || !b) return null
                  const x1 = COL[a.kind].x + COL[a.kind].w
                  const x2 = COL[b.kind].x
                  const y1 = (layout.top.get(a.id) ?? 0) + NODE_H / 2
                  const y2 = (layout.top.get(b.id) ?? 0) + NODE_H / 2
                  const mid = (x1 + x2) / 2
                  const hot = critical.has(e.from) && critical.has(e.to)
                  return (
                    <path
                      key={e.from + '>' + e.to}
                      d={`M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`}
                      fill="none" stroke={hot ? 'var(--crit)' : 'var(--line-strong)'} strokeWidth={hot ? 2.4 : 1.2}
                    />
                  )
                })}
                {graph.nodes.map(box)}
              </svg>
            </div>
          )}
        </Panel>

        {sel?.finding && (
          <Panel title={sel.finding.name} sub={`${sel.tactic?.name} (${sel.tactic?.id}) · ${sel.finding.source}`} className="mt-24">
            <div className="flex gap-12" style={{ alignItems: 'center', marginBottom: 12 }}>
              <span className={`pill ${severityPill[sel.finding.severity as Severity]}`}><span className="pd" />{sel.finding.severity}</span>
              <span className={`pill ${sel.finding.confidence === 'confirmed' ? 'pill-ok' : 'pill-warn'}`}><span className="pd" />{sel.finding.confidence}</span>
              {latestRetest(sel.finding) && <span className="small muted">last retest: {latestRetest(sel.finding)!.status}</span>}
            </div>
            <div className="mono small" style={{ wordBreak: 'break-all' }}>{sel.finding.target}{sel.finding.port != null ? `:${sel.finding.port}` : ''}</div>
            <div className="small muted mt-8">Evidence: {sel.finding.evidence}</div>
            {sel.finding.remediation && <div className="small mt-8">Remediation: {sel.finding.remediation}</div>}
            {sel.finding.mitre?.length ? <div className="small muted mt-8">ATT&CK: {sel.finding.mitre.join(', ')}</div> : null}
          </Panel>
        )}
      </div>
    </>
  )
}
