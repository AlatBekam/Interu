// Interu Rule-Engine DSL — a tiny, SAFE expression language for matchers and
// extractors, modeled on Nuclei's `dsl` helper expressions.
//
// IMPORTANT: there is NO JavaScript `eval` anywhere here. An expression is
// tokenized, parsed into an AST by a hand-written recursive-descent parser, and
// evaluated against a FIXED context of response facts. A template therefore can
// never run arbitrary code inside the app — the worst a bad expression can do is
// evaluate to false (or throw a DslError we catch). Framework-free so the main
// process, preload and renderer can all import it.
//
// Supported:
//   values      123   1.5   "str"   'str'   true   false
//   variables   status content_length duration body header response banner
//               host port service scheme  (any identifier; unknown → null)
//   operators   ! -   * / %   + -   < <= > >=   == !=   && ||
//   functions   len(x) contains(a,b) icontains(a,b) startswith(a,b)
//               endswith(a,b) regex(pattern,s) tolower(s) toupper(s)
//               int(x) str(x) trim(s)
//
// Strings concatenate with `+` when either side is non-numeric; comparisons
// coerce to number for < <= > >= and compare by value for == !=.

export type DslValue = string | number | boolean | null
export type DslContext = Record<string, DslValue>

export class DslError extends Error {}

// ------------------------------------------------------------------- tokenizer

type TokType = 'num' | 'str' | 'ident' | 'op' | 'lparen' | 'rparen' | 'comma' | 'eof'
interface Token { type: TokType; value: string }

const TWO_CHAR = new Set(['==', '!=', '<=', '>=', '&&', '||'])
const ONE_CHAR_OP = new Set(['!', '<', '>', '+', '-', '*', '/', '%'])

function tokenize(src: string): Token[] {
  const toks: Token[] = []
  let i = 0
  const n = src.length
  while (i < n) {
    const c = src[i]
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i++; continue }
    // strings — single or double quoted, with \\ and \" / \' escapes
    if (c === '"' || c === "'") {
      const quote = c
      let j = i + 1
      let out = ''
      while (j < n && src[j] !== quote) {
        if (src[j] === '\\' && j + 1 < n) { out += src[j + 1]; j += 2; continue }
        out += src[j]; j++
      }
      if (j >= n) throw new DslError('unterminated string')
      toks.push({ type: 'str', value: out })
      i = j + 1
      continue
    }
    // numbers
    if (c >= '0' && c <= '9') {
      let j = i
      while (j < n && ((src[j] >= '0' && src[j] <= '9') || src[j] === '.')) j++
      toks.push({ type: 'num', value: src.slice(i, j) })
      i = j
      continue
    }
    // identifiers (letters, digits, _; must start with letter/_)
    if (/[A-Za-z_]/.test(c)) {
      let j = i
      while (j < n && /[A-Za-z0-9_]/.test(src[j])) j++
      toks.push({ type: 'ident', value: src.slice(i, j) })
      i = j
      continue
    }
    if (c === '(') { toks.push({ type: 'lparen', value: c }); i++; continue }
    if (c === ')') { toks.push({ type: 'rparen', value: c }); i++; continue }
    if (c === ',') { toks.push({ type: 'comma', value: c }); i++; continue }
    const two = src.slice(i, i + 2)
    if (TWO_CHAR.has(two)) { toks.push({ type: 'op', value: two }); i += 2; continue }
    if (ONE_CHAR_OP.has(c)) { toks.push({ type: 'op', value: c }); i++; continue }
    throw new DslError(`unexpected character '${c}'`)
  }
  toks.push({ type: 'eof', value: '' })
  return toks
}

// ---------------------------------------------------------------------- parser

type Node =
  | { k: 'num'; v: number }
  | { k: 'str'; v: string }
  | { k: 'bool'; v: boolean }
  | { k: 'var'; name: string }
  | { k: 'call'; name: string; args: Node[] }
  | { k: 'unary'; op: string; e: Node }
  | { k: 'bin'; op: string; l: Node; r: Node }

class Parser {
  private p = 0
  constructor(private toks: Token[]) {}
  private peek(): Token { return this.toks[this.p] }
  private next(): Token { return this.toks[this.p++] }
  private expect(type: TokType): Token {
    const t = this.next()
    if (t.type !== type) throw new DslError(`expected ${type}, got '${t.value || t.type}'`)
    return t
  }

  parse(): Node {
    const e = this.parseOr()
    if (this.peek().type !== 'eof') throw new DslError(`unexpected '${this.peek().value}'`)
    return e
  }
  private parseOr(): Node {
    let l = this.parseAnd()
    while (this.peek().type === 'op' && this.peek().value === '||') { this.next(); l = { k: 'bin', op: '||', l, r: this.parseAnd() } }
    return l
  }
  private parseAnd(): Node {
    let l = this.parseEquality()
    while (this.peek().type === 'op' && this.peek().value === '&&') { this.next(); l = { k: 'bin', op: '&&', l, r: this.parseEquality() } }
    return l
  }
  private parseEquality(): Node {
    let l = this.parseComparison()
    while (this.peek().type === 'op' && (this.peek().value === '==' || this.peek().value === '!=')) {
      const op = this.next().value; l = { k: 'bin', op, l, r: this.parseComparison() }
    }
    return l
  }
  private parseComparison(): Node {
    let l = this.parseAdd()
    while (this.peek().type === 'op' && ['<', '>', '<=', '>='].includes(this.peek().value)) {
      const op = this.next().value; l = { k: 'bin', op, l, r: this.parseAdd() }
    }
    return l
  }
  private parseAdd(): Node {
    let l = this.parseMul()
    while (this.peek().type === 'op' && (this.peek().value === '+' || this.peek().value === '-')) {
      const op = this.next().value; l = { k: 'bin', op, l, r: this.parseMul() }
    }
    return l
  }
  private parseMul(): Node {
    let l = this.parseUnary()
    while (this.peek().type === 'op' && ['*', '/', '%'].includes(this.peek().value)) {
      const op = this.next().value; l = { k: 'bin', op, l, r: this.parseUnary() }
    }
    return l
  }
  private parseUnary(): Node {
    if (this.peek().type === 'op' && (this.peek().value === '!' || this.peek().value === '-')) {
      const op = this.next().value; return { k: 'unary', op, e: this.parseUnary() }
    }
    return this.parsePrimary()
  }
  private parsePrimary(): Node {
    const t = this.peek()
    if (t.type === 'num') { this.next(); return { k: 'num', v: Number(t.value) } }
    if (t.type === 'str') { this.next(); return { k: 'str', v: t.value } }
    if (t.type === 'lparen') { this.next(); const e = this.parseOr(); this.expect('rparen'); return e }
    if (t.type === 'ident') {
      this.next()
      if (t.value === 'true') return { k: 'bool', v: true }
      if (t.value === 'false') return { k: 'bool', v: false }
      if (this.peek().type === 'lparen') {
        this.next()
        const args: Node[] = []
        if (this.peek().type !== 'rparen') {
          args.push(this.parseOr())
          while (this.peek().type === 'comma') { this.next(); args.push(this.parseOr()) }
        }
        this.expect('rparen')
        return { k: 'call', name: t.value, args }
      }
      return { k: 'var', name: t.value }
    }
    throw new DslError(`unexpected '${t.value || t.type}'`)
  }
}

// ------------------------------------------------------------------- evaluator

function isNum(v: DslValue): v is number { return typeof v === 'number' && !Number.isNaN(v) }
function toNum(v: DslValue): number {
  if (typeof v === 'number') return v
  if (typeof v === 'boolean') return v ? 1 : 0
  if (v == null) return NaN
  const n = Number(v)
  return n
}
function toStr(v: DslValue): string {
  if (v == null) return ''
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  return String(v)
}
export function truthy(v: DslValue): boolean {
  if (typeof v === 'boolean') return v
  if (typeof v === 'number') return v !== 0 && !Number.isNaN(v)
  if (typeof v === 'string') return v.length > 0
  return false
}

const FUNCS: Record<string, (args: DslValue[]) => DslValue> = {
  len: (a) => toStr(a[0]).length,
  contains: (a) => toStr(a[0]).includes(toStr(a[1])),
  icontains: (a) => toStr(a[0]).toLowerCase().includes(toStr(a[1]).toLowerCase()),
  startswith: (a) => toStr(a[0]).startsWith(toStr(a[1])),
  endswith: (a) => toStr(a[0]).endsWith(toStr(a[1])),
  tolower: (a) => toStr(a[0]).toLowerCase(),
  toupper: (a) => toStr(a[0]).toUpperCase(),
  trim: (a) => toStr(a[0]).trim(),
  int: (a) => Math.trunc(toNum(a[0])),
  str: (a) => toStr(a[0]),
  regex: (a) => {
    try { return new RegExp(toStr(a[0])).test(toStr(a[1])) } catch { return false }
  }
}

function evalNode(node: Node, ctx: DslContext): DslValue {
  switch (node.k) {
    case 'num': return node.v
    case 'str': return node.v
    case 'bool': return node.v
    case 'var': return node.name in ctx ? ctx[node.name] : null
    case 'call': {
      const fn = FUNCS[node.name]
      if (!fn) throw new DslError(`unknown function '${node.name}'`)
      return fn(node.args.map((a) => evalNode(a, ctx)))
    }
    case 'unary': {
      const v = evalNode(node.e, ctx)
      return node.op === '!' ? !truthy(v) : -toNum(v)
    }
    case 'bin': {
      const { op } = node
      // Short-circuit logicals.
      if (op === '&&') return truthy(evalNode(node.l, ctx)) && truthy(evalNode(node.r, ctx))
      if (op === '||') return truthy(evalNode(node.l, ctx)) || truthy(evalNode(node.r, ctx))
      const l = evalNode(node.l, ctx)
      const r = evalNode(node.r, ctx)
      switch (op) {
        case '+':
          return isNum(l) && isNum(r) ? l + r : toStr(l) + toStr(r)
        case '-': return toNum(l) - toNum(r)
        case '*': return toNum(l) * toNum(r)
        case '/': return toNum(l) / toNum(r)
        case '%': return toNum(l) % toNum(r)
        case '<': return toNum(l) < toNum(r)
        case '>': return toNum(l) > toNum(r)
        case '<=': return toNum(l) <= toNum(r)
        case '>=': return toNum(l) >= toNum(r)
        case '==':
          return isNum(l) && isNum(r) ? l === r : toStr(l) === toStr(r)
        case '!=':
          return isNum(l) && isNum(r) ? l !== r : toStr(l) !== toStr(r)
        default: throw new DslError(`unknown operator '${op}'`)
      }
    }
  }
}

// Compile cache so a template's expressions parse once.
const cache = new Map<string, Node>()
function compile(expr: string): Node {
  const hit = cache.get(expr)
  if (hit) return hit
  const ast = new Parser(tokenize(expr)).parse()
  cache.set(expr, ast)
  return ast
}

/** Evaluate a DSL expression to a value. Throws DslError on a bad expression. */
export function evaluate(expr: string, ctx: DslContext): DslValue {
  return evalNode(compile(expr), ctx)
}

/** Evaluate an expression to a boolean; a parse/eval error counts as false. */
export function evalBool(expr: string, ctx: DslContext): boolean {
  try { return truthy(evaluate(expr, ctx)) } catch { return false }
}
