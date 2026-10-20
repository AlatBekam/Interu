import React, { useMemo, useState } from 'react'
import TopBar from '../../components/TopBar'
import { Panel, Disclaimer, Stat, Gauge } from '../../components/ui'
import { IconSequence, IconPlay } from '../../components/icons'
import { sampleTokens } from '../../data/burp'

// Shannon entropy over the character distribution of the captured tokens.
// This is a REAL calculation over the (simulated) sample tokens — it just does
// not capture anything from a live target.
function shannonBitsPerChar(tokens: string[]): number {
  const freq: Record<string, number> = {}
  let total = 0
  for (const t of tokens) for (const ch of t) { freq[ch] = (freq[ch] || 0) + 1; total++ }
  if (!total) return 0
  let h = 0
  for (const k in freq) { const p = freq[k] / total; h -= p * Math.log2(p) }
  return h
}

export default function Sequencer() {
  const [count, setCount] = useState(200)
  const tokens = useMemo(() => sampleTokens(count), [count])
  const [analyzed, setAnalyzed] = useState(false)

  const bpc = useMemo(() => shannonBitsPerChar(tokens), [tokens])
  const perToken = bpc * 20 // tokens are 20 chars
  const qualityPct = Math.min(100, Math.round((bpc / Math.log2(62)) * 100)) // 62-char alphabet ceiling
  const verdict = qualityPct > 90 ? { t: 'Excellent', c: 'pill-ok' } : qualityPct > 75 ? { t: 'Good', c: 'pill-info' } : qualityPct > 55 ? { t: 'Poor', c: 'pill-warn' } : { t: 'Weak', c: 'pill-crit' }

  // per-position entropy for the bar visualization
  const positional = useMemo(() => {
    const cols = 20
    const out: number[] = []
    for (let c = 0; c < cols; c++) {
      const freq: Record<string, number> = {}
      for (const t of tokens) { const ch = t[c]; freq[ch] = (freq[ch] || 0) + 1 }
      let h = 0
      for (const k in freq) { const p = freq[k] / tokens.length; h -= p * Math.log2(p) }
      out.push(h)
    }
    return out
  }, [tokens])
  const maxH = Math.max(...positional, 1)

  return (
    <>
      <TopBar title="Sequencer" sub="Token randomness analysis" />
      <div className="content page">
        <Disclaimer>
          Tokens here are <strong>generated locally</strong> for the demo, not captured from a target. The
          entropy maths are real; the sample is simulated. Later this would analyze tokens from authorized tests.
        </Disclaimer>

        <div className="flex gap-12 items-center mt-16 mb-16 wrap">
          <label className="field" style={{ width: 200 }}><span className="lab">Sample size</span>
            <select value={count} onChange={(e) => { setCount(Number(e.target.value)); setAnalyzed(false) }}>
              {[50, 100, 200, 500].map((n) => <option key={n} value={n}>{n} tokens</option>)}
            </select>
          </label>
          <button className="btn btn-primary" onClick={() => setAnalyzed(true)} style={{ alignSelf: 'end' }}><IconPlay />Analyze</button>
        </div>

        {analyzed ? (
          <>
            <div className="grid grid-4">
              <Stat label="Sample" value={count} meta="tokens · 20 chars" icon={<IconSequence />} />
              <Stat label="Entropy / char" value={bpc.toFixed(2)} meta="bits (max 5.95)" />
              <Stat label="Entropy / token" value={Math.round(perToken)} meta="bits estimated" />
              <Stat label="Quality" value={`${qualityPct}%`} meta={<span className={`pill ${verdict.c}`}><span className="pd" />{verdict.t}</span>} />
            </div>

            <div className="grid grid-3 mt-24">
              <Panel title="Overall Quality" sub="Simulated">
                <div className="gauge-wrap">
                  <Gauge value={qualityPct} label="Score" />
                  <div className="small muted">Ratio of observed per-character entropy to the theoretical maximum for the token alphabet.</div>
                </div>
              </Panel>
              <Panel title="Per-position Entropy" sub="Bits at each of the 20 character slots" className="span-2">
                <div style={{ display: 'flex', alignItems: 'flex-end', gap: 4, height: 150 }}>
                  {positional.map((h, i) => (
                    <div key={i} title={`pos ${i + 1}: ${h.toFixed(2)} bits`} style={{ flex: 1, height: `${(h / maxH) * 100}%`, background: 'linear-gradient(180deg, var(--royal-bright), var(--navy))', borderRadius: '3px 3px 0 0', minHeight: 4 }} />
                  ))}
                </div>
                <div className="small muted mt-8">Even bars indicate uniform randomness across positions.</div>
              </Panel>
            </div>
          </>
        ) : (
          <Panel title="Live Capture" sub={`${tokens.length} sample tokens`}>
            <div className="code-pane" style={{ minHeight: 240 }}>{tokens.slice(0, 40).join('\n')}{tokens.length > 40 ? `\n… +${tokens.length - 40} more` : ''}</div>
            <div className="small muted mt-8">Press <strong>Analyze</strong> to compute entropy and quality.</div>
          </Panel>
        )}
      </div>
    </>
  )
}
