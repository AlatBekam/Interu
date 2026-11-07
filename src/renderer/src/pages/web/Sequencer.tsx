import React, { useMemo, useState } from 'react'
import TopBar from '../../components/TopBar'
import { Panel, Disclaimer, Stat, Gauge } from '../../components/ui'
import { IconSequence, IconPlay } from '../../components/icons'
import { analyzeTokens, parseTokens } from '../../../../shared/tokens'
import { usePersistentState } from '../../store/store'

export default function Sequencer() {
  const [text, setText] = usePersistentState('sequencer.tokens', '')
  const [analyzed, setAnalyzed] = useState(false)

  const tokens = useMemo(() => parseTokens(text), [text])
  const a = useMemo(() => analyzeTokens(tokens), [tokens])
  const verdict = !a ? null
    : a.qualityPct > 90 ? { t: 'Excellent', c: 'pill-ok' }
    : a.qualityPct > 75 ? { t: 'Good', c: 'pill-info' }
    : a.qualityPct > 55 ? { t: 'Poor', c: 'pill-warn' }
    : { t: 'Weak', c: 'pill-crit' }
  const maxH = a ? Math.max(...a.positional, 1) : 1

  return (
    <>
      <TopBar title="Sequencer" sub="Token randomness analysis" />
      <div className="content page">
        <Disclaimer>
          Paste session IDs, CSRF tokens or other values collected during an authorized test, one per line. The
          entropy is computed locally; nothing is sent anywhere. Use at least a few dozen tokens for a meaningful result.
        </Disclaimer>

        <Panel title="Tokens" sub={`${tokens.length} unique`} className="mt-16"
          right={<button className="btn btn-primary btn-sm" onClick={() => setAnalyzed(true)} disabled={tokens.length < 2}><IconPlay />Analyze</button>}>
          <textarea
            className="code-pane"
            value={text}
            onChange={(e) => { setText(e.target.value); setAnalyzed(false) }}
            placeholder="One token per line"
            style={{ minHeight: 200 }}
            spellCheck={false}
          />
          {tokens.length < 2 && <div className="small muted mt-8">Paste at least 2 distinct tokens to analyze.</div>}
        </Panel>

        {analyzed && a && verdict && (
          <>
            <div className="grid grid-4 mt-24">
              <Stat label="Sample" value={a.count} meta={`tokens · avg ${a.avgLen.toFixed(1)} chars`} icon={<IconSequence />} />
              <Stat label="Entropy / char" value={a.bitsPerChar.toFixed(2)} meta={`bits (max ${a.maxBitsPerChar.toFixed(2)}, ${a.charset})`} />
              <Stat label="Entropy / token" value={Math.round(a.bitsPerToken)} meta="bits estimated" />
              <Stat label="Quality" value={`${a.qualityPct}%`} meta={<span className={`pill ${verdict.c}`}><span className="pd" />{verdict.t}</span>} />
            </div>

            <div className="grid grid-3 mt-24">
              <Panel title="Overall Quality">
                <div className="gauge-wrap">
                  <Gauge value={a.qualityPct} label="Score" tone="quality" />
                  <div className="small muted">Observed per-character entropy as a share of the maximum for the detected charset.</div>
                </div>
              </Panel>
              <Panel title="Per-position Entropy" sub={`Bits at each of the ${a.positional.length} character slots`} className="span-2">
                <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 150 }}>
                  {a.positional.map((h, i) => (
                    <div key={i} className="bar-col" title={`pos ${i + 1}: ${h.toFixed(2)} bits`} style={{ height: `${(h / maxH) * 100}%` }} />
                  ))}
                </div>
                <div className="small muted mt-8">Even bars indicate uniform randomness across positions; flat-zero bars are constant characters.</div>
              </Panel>
            </div>
          </>
        )}
      </div>
    </>
  )
}
