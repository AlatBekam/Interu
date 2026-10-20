import React, { useMemo, useState } from 'react'
import TopBar from '../../components/TopBar'
import { Panel, Disclaimer } from '../../components/ui'
import { IconColumns } from '../../components/icons'
import { rawResponse, HTTP_HISTORY } from '../../data/burp'

type DiffOp = { type: 'same' | 'add' | 'del'; text: string }

// Classic LCS line diff — real, offline computation.
function lineDiff(a: string[], b: string[]): DiffOp[] {
  const n = a.length, m = b.length
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0))
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--)
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1])
  const out: DiffOp[] = []
  let i = 0, j = 0
  while (i < n && j < m) {
    if (a[i] === b[j]) { out.push({ type: 'same', text: a[i] }); i++; j++ }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push({ type: 'del', text: a[i] }); i++ }
    else { out.push({ type: 'add', text: b[j] }); j++ }
  }
  while (i < n) out.push({ type: 'del', text: a[i++] })
  while (j < m) out.push({ type: 'add', text: b[j++] })
  return out
}

const LEFT = rawResponse(HTTP_HISTORY[5]) // /api/orders?id=1001 (200)
const RIGHT = rawResponse(HTTP_HISTORY[6]) // /api/orders?id=1002 (403)

export default function Comparer() {
  const [left, setLeft] = useState(LEFT)
  const [right, setRight] = useState(RIGHT)
  const [compared, setCompared] = useState(false)

  const diff = useMemo(() => lineDiff(left.split('\n'), right.split('\n')), [left, right])
  const stats = useMemo(() => ({
    add: diff.filter((d) => d.type === 'add').length,
    del: diff.filter((d) => d.type === 'del').length,
    same: diff.filter((d) => d.type === 'same').length
  }), [diff])

  return (
    <>
      <TopBar title="Comparer" sub="Diff two responses — offline" />
      <div className="content page">
        <Disclaimer>
          A real, <strong>offline</strong> line-level diff. Pre-loaded with two simulated responses (a 200 vs a
          403 for different order IDs) to show a classic access-control comparison.
        </Disclaimer>

        <div className="split mt-16">
          <Panel title="Item A" sub="simulated response (200)">
            <textarea className="code-pane" value={left} onChange={(e) => { setLeft(e.target.value); setCompared(false) }} style={{ minHeight: 220 }} spellCheck={false} />
          </Panel>
          <Panel title="Item B" sub="simulated response (403)">
            <textarea className="code-pane" value={right} onChange={(e) => { setRight(e.target.value); setCompared(false) }} style={{ minHeight: 220 }} spellCheck={false} />
          </Panel>
        </div>

        <div className="flex gap-12 items-center mt-16">
          <button className="btn btn-primary" onClick={() => setCompared(true)}><IconColumns />Compare</button>
          {compared && (
            <div className="flex gap-12 small">
              <span className="pill pill-ok"><span className="pd" />{stats.add} added</span>
              <span className="pill pill-crit"><span className="pd" />{stats.del} removed</span>
              <span className="pill pill-muted"><span className="pd" />{stats.same} unchanged</span>
            </div>
          )}
        </div>

        {compared && (
          <Panel title="Differences" sub="A → B" className="mt-24">
            <div style={{ fontFamily: 'var(--font-mono)' }}>
              {diff.map((d, i) => (
                <div key={i} className={`diff-line ${d.type === 'add' ? 'diff-add' : d.type === 'del' ? 'diff-del' : 'diff-same'}`}>
                  <span style={{ opacity: 0.6, userSelect: 'none' }}>{d.type === 'add' ? '+ ' : d.type === 'del' ? '- ' : '  '}</span>
                  {d.text || ' '}
                </div>
              ))}
            </div>
          </Panel>
        )}
      </div>
    </>
  )
}
