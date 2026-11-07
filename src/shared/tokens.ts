// Token randomness analysis for the Sequencer. Pure functions: the tokens come from
// the operator (pasted from an authorized test), nothing is generated here.

/** One token per non-empty trimmed line; duplicates removed, order kept. */
export function parseTokens(text: string): string[] {
  const seen = new Set<string>()
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim()
    if (t) seen.add(t)
  }
  return [...seen]
}

export interface TokenAnalysis {
  count: number
  avgLen: number
  /** Shannon entropy over the pooled character distribution, bits per character. */
  bitsPerChar: number
  /** Ceiling for the detected charset (hex 4, digits ~3.32, base64url 6, printable ~6.55). */
  maxBitsPerChar: number
  charset: string
  bitsPerToken: number
  qualityPct: number
  /** Entropy at each character position, over tokens long enough to have it. */
  positional: number[]
}

function charsetOf(tokens: string[]): { name: string; size: number } {
  const all = tokens.join('')
  if (/^[0-9]+$/.test(all)) return { name: 'digits', size: 10 }
  if (/^[0-9a-fA-F]+$/.test(all)) return { name: 'hex', size: 16 }
  if (/^[A-Za-z0-9_-]+$/.test(all)) return { name: 'base64url', size: 64 }
  return { name: 'printable', size: 94 }
}

const entropy = (freq: Map<string, number>, total: number): number => {
  let h = 0
  for (const n of freq.values()) { const p = n / total; h -= p * Math.log2(p) }
  return h
}

/** Returns null for fewer than 2 tokens: entropy of a single value says nothing. */
export function analyzeTokens(tokens: string[]): TokenAnalysis | null {
  if (tokens.length < 2) return null
  const pooled = new Map<string, number>()
  let total = 0
  for (const t of tokens) for (const ch of t) { pooled.set(ch, (pooled.get(ch) ?? 0) + 1); total++ }
  if (total === 0) return null
  const bitsPerChar = entropy(pooled, total)
  const cs = charsetOf(tokens)
  const maxBitsPerChar = Math.log2(cs.size)
  const avgLen = total / tokens.length

  const cols = Math.min(64, Math.max(...tokens.map((t) => t.length)))
  const positional: number[] = []
  for (let c = 0; c < cols; c++) {
    const freq = new Map<string, number>()
    let n = 0
    for (const t of tokens) if (c < t.length) { freq.set(t[c], (freq.get(t[c]) ?? 0) + 1); n++ }
    positional.push(n > 1 ? entropy(freq, n) : 0)
  }

  return {
    count: tokens.length,
    avgLen,
    bitsPerChar,
    maxBitsPerChar,
    charset: cs.name,
    bitsPerToken: bitsPerChar * avgLen,
    qualityPct: Math.min(100, Math.round((bitsPerChar / maxBitsPerChar) * 100)),
    positional
  }
}
