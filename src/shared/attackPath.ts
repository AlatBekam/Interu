// Attack-path model: correlates findings from every module into one graph per
// host — host → service (port) → finding — tagged with a MITRE ATT&CK tactic,
// and marks the critical path (the worst confirmed finding). Framework-free.

import type { Finding } from './rules'
import { SEVERITY_RANK, sortFindings } from './rules'

export interface Tactic { id: string; name: string; order: number }

const TACTICS: Record<string, Tactic> = {
  TA0007: { id: 'TA0007', name: 'Discovery', order: 1 },
  TA0001: { id: 'TA0001', name: 'Initial Access', order: 2 },
  TA0006: { id: 'TA0006', name: 'Credential Access', order: 3 },
  TA0008: { id: 'TA0008', name: 'Lateral Movement', order: 4 }
}

// Techniques referenced by the templates in rules.ts.
const TECHNIQUE_TACTIC: Record<string, string> = { T1021: 'TA0008', 'T1021.001': 'TA0008', 'T1021.002': 'TA0008' }

/**
 * Tactic for a finding: from its MITRE technique when the template has one,
 * otherwise a heuristic — exposed services are Discovery, web weaknesses are
 * Initial Access (public-facing application), leaked secrets are Credential Access.
 */
export function tacticOf(f: Finding): Tactic {
  for (const t of f.mitre || []) {
    const ta = TECHNIQUE_TACTIC[t] || TECHNIQUE_TACTIC[t.split('.')[0]]
    if (ta) return TACTICS[ta]
  }
  if (f.tags?.includes('secrets')) return TACTICS.TA0006
  return f.source === 'scanner' ? TACTICS.TA0007 : TACTICS.TA0001
}

export interface GraphNode {
  id: string
  kind: 'host' | 'service' | 'finding'
  label: string
  host: string
  finding?: Finding
  tactic?: Tactic
}

export interface AttackGraph {
  nodes: GraphNode[]
  edges: { from: string; to: string }[]
  /** node ids from host to the worst confirmed finding; empty when nothing is confirmed. */
  critical: string[]
}

function locate(f: Finding): { host: string; port?: number; scheme?: string } {
  try {
    const u = new URL(f.target)
    const scheme = u.protocol.replace(':', '')
    return { host: u.hostname, port: u.port ? Number(u.port) : scheme === 'https' ? 443 : 80, scheme }
  } catch {
    return { host: f.target, port: f.port }
  }
}

export function buildAttackGraph(findings: Finding[]): AttackGraph {
  const nodes = new Map<string, GraphNode>()
  const edges: { from: string; to: string }[] = []
  const edgeSeen = new Set<string>()
  const link = (from: string, to: string): void => {
    if (edgeSeen.has(from + '>' + to)) return
    edgeSeen.add(from + '>' + to)
    edges.push({ from, to })
  }
  const pathOf = new Map<string, string[]>()

  for (const f of sortFindings(findings)) {
    const { host, port, scheme } = locate(f)
    const hostId = `host:${host}`
    if (!nodes.has(hostId)) nodes.set(hostId, { id: hostId, kind: 'host', label: host, host })
    let parent = hostId
    const path = [hostId]
    if (port != null) {
      const svcId = `svc:${host}:${port}`
      if (!nodes.has(svcId)) nodes.set(svcId, { id: svcId, kind: 'service', label: `${port}${scheme ? '/' + scheme : ''}`, host })
      link(hostId, svcId)
      parent = svcId
      path.push(svcId)
    }
    const fid = `finding:${f.key}`
    nodes.set(fid, { id: fid, kind: 'finding', label: f.name, host, finding: f, tactic: tacticOf(f) })
    link(parent, fid)
    path.push(fid)
    pathOf.set(f.key, path)
  }

  const worst = findings
    .filter((f) => f.confidence === 'confirmed')
    .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.key.localeCompare(b.key))[0]
  return { nodes: Array.from(nodes.values()), edges, critical: worst ? pathOf.get(worst.key) || [] : [] }
}
