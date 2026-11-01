# Exposure Monitor (real activity) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Threat Monitor's synthetic event feed with real activity from Interu itself plus a findings-based exposure view, and delete the dummy generators.

**Architecture:** A pure module (`src/shared/activity.ts`) derives events, a priority queue, per-host exposure and summary counts from findings. An in-memory renderer store (`store/activity.ts`, same `useSyncExternalStore` pattern as `store/findings.ts`) keeps the last 200 events. Existing flows push events (findings store, scanner lifecycle, scope decisions, proxy intercept holds); the renamed page and the Dashboard read them. No new IPC, no network.

**Tech Stack:** TypeScript, React 18, Electron renderer, vitest 2 (unit), playwright-core (GUI e2e).

**Spec:** the "Spec" section below (design agreed with the user on 2026-11-01; no separate spec file). On approval this plan is also saved to `docs/superpowers/plans/2026-11-01-exposure-monitor.md`.

## Spec (agreed with the user)

- The page "Threat Monitor" becomes **"Exposure Monitor"**; route `/threats` is unchanged.
- It shows only what Interu itself observed: findings, scan lifecycle, scope decisions, proxy intercept holds, plus the CISA KEV snapshot. It is not an intrusion-detection system and says so.
- Content: 4 stat cards, a priority queue (KEV first), an activity timeline, exposure by host, a KEV snapshot line, and empty states.
- Remove `generateEvent`, `seedEvents`, `SOURCES`, `FEED_TEMPLATES` and `ThreatEvent` from `data/mock.ts` (keep `makeRng`, `trafficSeries` uses it), and remove the `liveFeed` setting and its Settings row.
- The Dashboard "Recent Activity" panel shows the same real events.
- Out of scope: Firewall page, `MOCK_HOSTS`, `MOCK_VULNS`, host/OS telemetry (Windows Event Log, IDS), persistence of activity across restarts.

## Global Constraints

- Activity buffer: newest first, maximum **200** events, in memory only.
- Level mapping: `critical`/`high` → `crit`, `medium` → `warn`, `low`/`info` → `info`; a finding with KEV entries is always `crit`; a resolved finding is `ok`.
- Exact messages: `New finding: ${name}`, `Resolved: ${name}`, `Scan started: ${target} (${profile})`, `Scan finished: ${hostsUp} host(s) up, ${openPortCount} open port(s)`, `Blocked by scope: ${target} (${via})`, `Request held: ${method} ${host}`.
- Categories: `finding`, `scan`, `scope`, `proxy`.
- The KEV work (`src/shared/kev.ts`, `kev-index.ts`, `Finding.kev`, `kevTooltip`) is on branch `feat/kev-cve-tagging` and is **uncommitted**: never `git add -A` or `git add .`; always add explicit paths.
- UI strings are English (like the existing pages); docs are Indonesian; docs files use CRLF line endings.
- No new dependencies; do not touch Firewall, `MOCK_HOSTS`, `MOCK_VULNS`, `trafficSeries`.
- GUI e2e needs no other Interu window running (single-instance lock); ask before stopping one, and stop only processes from this project's `node_modules`.

## Review Focus

- A finding target is a bare IP (scanner), `host:port`, or a full URL with path (active/proxy); all must group under one host row. Pinned in Task 1.
- Zero findings and zero events: the page and the Dashboard show an empty state, not blank cards or `NaN`. Pinned in Task 6.
- A big scan can add hundreds of findings at once: the buffer must stay at 200 and stay newest-first. Pinned in Task 2.
- Re-running the same scan re-adds findings with the same key: it must not repeat "New finding" events. Pinned in Task 3.
- A browser profile that already stored the removed `liveFeed` setting must still load. Pinned in Task 4 (settings are merged as `{ ...DEFAULT_SETTINGS, ...stored }`, so the extra key is ignored).

---

### Task 1: Pure activity logic

**Files:**
- Create: `src/shared/activity.ts`
- Test: `src/shared/activity.test.ts`

**Interfaces:**
- Consumes: `Finding`, `RuleSeverity`, `SEVERITY_RANK` from `src/shared/rules.ts`.
- Produces (exact):
  - `type ActivityLevel = 'info' | 'warn' | 'crit' | 'ok'`
  - `type ActivityCategory = 'finding' | 'scan' | 'scope' | 'proxy'`
  - `interface ActivityEvent { id: string; ts: string /* ISO */; level: ActivityLevel; category: ActivityCategory; message: string; target?: string }`
  - `type ActivityDraft = Omit<ActivityEvent, 'id'>`
  - `hostOf(target: string): string`
  - `severityLevel(s: RuleSeverity): ActivityLevel`
  - `eventFromFinding(f: Finding, at?: string): ActivityDraft`
  - `priorityQueue(findings: Finding[], limit?: number): Finding[]`
  - `interface TargetExposure { host: string; total: number; bySeverity: Record<RuleSeverity, number>; kev: number }`
  - `exposureByTarget(findings: Finding[]): TargetExposure[]`
  - `summarize(findings: Finding[]): { critHigh: number; confirmed: number; kev: number; hosts: number }`
  - `timeLabel(iso: string): string` (`HH:MM:SS`, 24 h)

- [ ] **Step 1: Write the failing tests** in `activity.test.ts`, using a helper `f(o: Partial<Finding>): Finding` (defaults: `severity:'low'`, `confidence:'confirmed'`, `target:'http://127.0.0.1:8090/x'`, `source:'active'`) and a `kev` fixture `{ cve: 'CVE-2021-3129', name: 'x', dateAdded: '2021-11-01', ransomware: false }`:
  - `hostOf` collapses `'http://127.0.0.1:8090/.gitlab-ci.yml'`, `'127.0.0.1'`, `'127.0.0.1:80'` to `'127.0.0.1'`, and `'https://shop.test/a?x=1'` to `'shop.test'`.
  - `severityLevel`: critical and high → `'crit'`, medium → `'warn'`, low and info → `'info'`.
  - `eventFromFinding(f({ severity: 'low', kev: [kev] }))` has `level 'crit'`, `category 'finding'`, `message 'New finding: N'` (with `name: 'N'`), `target` equal to the finding's target; without `kev` and `severity: 'medium'` the level is `'warn'`.
  - `priorityQueue`: a KEV-listed `low` finding precedes a non-KEV `critical`; then severity order; then `confirmed` before `suspected`; `limit` truncates (`priorityQueue(list, 2).length === 2`).
  - `exposureByTarget` merges a scanner finding (`target:'127.0.0.1'`, port set) and an active finding (`target:'http://127.0.0.1:8090/x'`) into one row `{ host: '127.0.0.1', total: 2 }` with correct `bySeverity` and `kev` counts; rows sort by `kev` desc, then critical count desc, then `total` desc.
  - `summarize` returns `critHigh`, `confirmed`, `kev` and distinct `hosts` counts for a mixed list; for `[]` all four are `0`.
  - `timeLabel('2026-11-01T14:05:09Z')` matches `/^\d{2}:\d{2}:\d{2}$/`.
- [ ] **Step 2: Run to verify failure**
  Run: `npx vitest run src/shared/activity.test.ts`
  Expected: FAIL (module not found).
- [ ] **Step 3: Implement** the signatures above in `src/shared/activity.ts`. `hostOf`: try `new URL(target).hostname`, otherwise strip a trailing `:port`. `priorityQueue` sorts a copy (never mutates input) by `kev?.length` presence, then `SEVERITY_RANK`, then confirmed-first, then `target`.
- [ ] **Step 4: Run to verify pass**
  Run: `npx vitest run src/shared/activity.test.ts`
  Expected: PASS.
- [ ] **Step 5: Commit**
  ```bash
  git add src/shared/activity.ts src/shared/activity.test.ts
  git commit -m "feat(monitor): pure activity logic (events, priority queue, exposure)"
  ```

### Task 2: Activity store

**Files:**
- Create: `src/renderer/src/store/activity.ts`
- Test: `src/renderer/src/store/activity.test.ts`

**Interfaces:**
- Consumes: `ActivityDraft`, `ActivityEvent` from Task 1.
- Produces (exact):
  - `pushActivity(d: ActivityDraft): void` (assigns a unique `id`, prepends, caps at 200)
  - `getActivity(): ActivityEvent[]`
  - `useActivity(): ActivityEvent[]`
  - `clearActivity(): void`
  - `noteScopeBlock(target: string, via: string): void` (pushes `{ level: 'warn', category: 'scope', message: 'Blocked by scope: <target> (<via>)', target }`)

- [ ] **Step 1: Write the failing tests:**
  - After `clearActivity()`, pushing 205 drafts with `message: 'm'+i` leaves `getActivity().length === 200`, `getActivity()[0].message === 'm204'`, and 200 distinct ids.
  - `noteScopeBlock('http://10.0.0.9/', 'repeater')` yields one event with `level 'warn'`, `category 'scope'`, `message 'Blocked by scope: http://10.0.0.9/ (repeater)'`, `target 'http://10.0.0.9/'`.
- [ ] **Step 2: Run to verify failure:** `npx vitest run src/renderer/src/store/activity.test.ts` (FAIL, module not found).
- [ ] **Step 3: Implement** the store in memory only (no `window` access at import, so it runs under node); copy the `listeners`/`emit`/`subscribe` shape from `store/findings.ts`; ids from a module counter.
- [ ] **Step 4: Run to verify pass:** same command (PASS).
- [ ] **Step 5: Commit**
  ```bash
  git add src/renderer/src/store/activity.ts src/renderer/src/store/activity.test.ts
  git commit -m "feat(monitor): in-memory activity store"
  ```

### Task 3: Wire the real sources

**Files:**
- Modify: `src/renderer/src/store/findings.ts` (`addFindings`, `removeFinding`)
- Modify: `src/renderer/src/lib/http.ts` (`sendLive`; new `inScopeOrNote`)
- Modify: `src/renderer/src/pages/RuleEngine.tsx` (scope pre-check at line 97; the three `blocked` branches at about lines 67, 112, 141)
- Modify: `src/renderer/src/pages/web/Intruder.tsx:74`, `Repeater.tsx:56`, `Target.tsx:59` (scope pre-checks)
- Modify: `src/renderer/src/pages/NetworkScanner.tsx` (`startLive`)
- Modify: `src/renderer/src/pages/web/Proxy.tsx` (`onIntercept` handler at about line 71)
- Test: `src/renderer/src/store/activity-sources.test.ts`

**Interfaces:**
- Consumes: `pushActivity`, `noteScopeBlock`, `clearActivity`, `getActivity` (Task 2); `eventFromFinding` (Task 1); `hostInScope` from `src/shared/http.ts`.
- Produces: `inScopeOrNote(url: string, scope: string[], via: string): boolean` in `lib/http.ts` (returns `hostInScope(url, scope)`; when false also calls `noteScopeBlock(url, via)`).

- [ ] **Step 1: Write the failing tests** (create findings with a `Finding` helper; call `clearFindings()` and `clearActivity()` in `beforeEach`):
  - `addFindings([x])` adds exactly one `finding` event whose message is `New finding: <name>`; a second `addFindings([x])` with the same key adds none.
  - `removeFinding(x.key)` adds one `ok` event `Resolved: <name>`; `clearFindings()` adds none.
  - `inScopeOrNote('http://10.0.0.9/', ['10.0.0.1'], 'repeater')` returns `false` and adds one `scope` event; `inScopeOrNote('http://10.0.0.1/', ['10.0.0.1'], 'repeater')` returns `true` and adds none.
- [ ] **Step 2: Run to verify failure:** `npx vitest run src/renderer/src/store/activity-sources.test.ts` (FAIL).
- [ ] **Step 3: Implement.**
  - `findings.ts`: in `addFindings`, for each incoming finding whose key was not in `byKey`, `pushActivity(eventFromFinding(f))`; in `removeFinding`, look the finding up before removing and push `{ level: 'ok', category: 'finding', message: 'Resolved: ' + name, target }`.
  - `lib/http.ts`: add `inScopeOrNote`; in `sendLive`, if the response has `blocked`, call `noteScopeBlock(req.url, 'http')`.
  - Replace the four `hostInScope(` pre-checks (RuleEngine, Intruder, Repeater, Target) with `inScopeOrNote(<same url>, settings.scope, '<rule-engine|intruder|repeater|target>')`; in RuleEngine's three `res.blocked` branches call `noteScopeBlock(<url>, 'rule-engine')`.
  - `NetworkScanner.startLive`: push `{ level:'info', category:'scan', message:'Scan started: <target> (<profile>)', target }` before `scan.run`; on `res.blocked` call `noteScopeBlock(target, 'scan')`; on success push `{ level:'ok', category:'scan', message:'Scan finished: <hostsUp> host(s) up, <openPortCount> open port(s)', target }` from `res.summary`.
  - `Proxy.tsx` `onIntercept`: push `{ level:'info', category:'proxy', message:'Request held: <h.method> <h.host>', target: h.host }`.
- [ ] **Step 4: Run to verify pass:** `npx vitest run` (all unit tests PASS) and `npm run typecheck` (exit 0).
- [ ] **Step 5: Commit** (explicit paths only)
  ```bash
  git add src/renderer/src/store/findings.ts src/renderer/src/lib/http.ts src/renderer/src/pages/RuleEngine.tsx src/renderer/src/pages/web/Intruder.tsx src/renderer/src/pages/web/Repeater.tsx src/renderer/src/pages/web/Target.tsx src/renderer/src/pages/NetworkScanner.tsx src/renderer/src/pages/web/Proxy.tsx src/renderer/src/store/activity-sources.test.ts
  git commit -m "feat(monitor): record findings, scans, scope decisions and intercepts as activity"
  ```
  Note: `RuleEngine.tsx` and `global.css` also hold uncommitted KEV changes; commit the KEV work first (with the user's approval) or stage hunks with `git add -p`.

### Task 4: Exposure Monitor page, naming, settings cleanup

**Files:**
- Modify: `src/renderer/src/pages/ThreatMonitor.tsx` (rewrite)
- Modify: `src/renderer/src/components/Sidebar.tsx:35` (label `'Exposure Monitor'`; route `/threats` unchanged)
- Modify: `src/renderer/src/pages/Settings.tsx:62-67` (delete the "Live threat feed" row)
- Modify: `src/renderer/src/store/store.ts` (remove `liveFeed` from the `Settings` interface and `DEFAULT_SETTINGS`)

**Interfaces:**
- Consumes: `useFindings`, `useActivity`, `clearActivity`, `priorityQueue`, `exposureByTarget`, `summarize`, `timeLabel`, `KEV_COUNT`, `KEV_CATALOG_VERSION`, `kevTooltip`, existing `Panel`/`Stat`/`Disclaimer`/`TopBar`.
- Produces: the page default export `ThreatMonitor` (component name unchanged to keep `App.tsx`).

- [ ] **Step 1: Implement the page.** `TopBar title="Exposure Monitor" sub="Findings, exposure and activity from your own scans"`; a `Disclaimer` stating it shows what Interu observed and is not an intrusion-detection system; stat cards "Critical / High", "Confirmed", "Actively exploited (KEV)" and "Hosts with findings" from `summarize(findings)`; a line `CISA KEV snapshot ${KEV_CATALOG_VERSION} · ${KEV_COUNT} entries`; panel "Priority queue" (`priorityQueue(findings, 10)`: Severity, Finding, Target, CVE with the red KEV pill) with empty state `No findings yet. Run a scan or active checks.`; panel "Exposure by host" (`exposureByTarget`: Host, Critical/High, Medium, Low/Info, KEV); panel "Activity" using the existing `.feed` markup (`timeLabel(e.ts)`, level pill, `[category]`, message), a **Clear** button calling `clearActivity()`, and empty state `No activity yet in this session.`.
- [ ] **Step 2: Remove the `liveFeed` setting** from `Settings.tsx` and `store.ts`. Confirm `store.ts` still merges stored settings as `{ ...DEFAULT_SETTINGS, ...read(...) }` (line 84) so a previously stored `liveFeed` key is harmless.
- [ ] **Step 3: Verify:** `npm run typecheck` (exit 0) and `npm run build` (exit 0). Behavior is asserted end to end in Task 6.
- [ ] **Step 4: Commit**
  ```bash
  git add src/renderer/src/pages/ThreatMonitor.tsx src/renderer/src/components/Sidebar.tsx src/renderer/src/pages/Settings.tsx src/renderer/src/store/store.ts
  git commit -m "feat(monitor): Exposure Monitor page on real findings and activity"
  ```

### Task 5: Dashboard on real activity, remove the dummy generators

**Files:**
- Modify: `src/renderer/src/pages/Dashboard.tsx` (import at line 5, `recent` at line 9, panel at lines 96-107)
- Modify: `src/renderer/src/data/mock.ts` (delete `SOURCES`, `FEED_TEMPLATES`, `generateEvent`, `seedEvents`, `ThreatEvent`; keep `makeRng`)

**Interfaces:**
- Consumes: `useActivity`, `timeLabel`.

- [ ] **Step 1: Implement.** `const recent = useActivity().slice(0, 6)`; panel `Recent Activity` with sub `Live activity`; render `timeLabel(e.ts)`, level pill and `e.message`; empty state `No activity yet.`. Remove `seedEvents` from the import.
- [ ] **Step 2: Delete the generators** from `mock.ts`; keep `makeRng` because `trafficSeries` uses it.
- [ ] **Step 3: Verify:** `grep -rn "seedEvents\|generateEvent\|ThreatEvent" src` returns nothing; `npm run typecheck` and `npm run build` exit 0; `npx vitest run` passes.
- [ ] **Step 4: Commit**
  ```bash
  git add src/renderer/src/pages/Dashboard.tsx src/renderer/src/data/mock.ts
  git commit -m "feat(monitor): Dashboard shows real activity; remove synthetic feed generators"
  ```

### Task 6: GUI e2e

**Files:**
- Create: `testcase/e2e/monitor.e2e.ts`

**Interfaces:**
- Consumes: `launchApp`, `nav`, `shot` from `testcase/e2e/helpers/app.ts`; sidebar label `Exposure Monitor`.

- [ ] **Step 1: Write the spec** (local server on `127.0.0.1:8090` serving `/.gitlab-ci.yml` with body `stages:\n  - build\nscript:\n  - make\n` and `404` elsewhere; scope `127.0.0.1` only; start by clearing scope and findings, clean up at the end). Tests:
  - `starts empty with no synthetic data`: on `Exposure Monitor` the body contains `No activity yet` and `No findings yet`, and contains neither `trojan beacon` nor `synthetically generated`.
  - `a real finding reaches queue, exposure and activity`: run active checks against `http://127.0.0.1:8090/`; on the monitor, the queue lists `Exposed .gitlab-ci.yml`, the exposure table has a `127.0.0.1` row, and the activity feed contains `New finding: Exposed .gitlab-ci.yml`.
  - `the Dashboard shows the same activity`: `Recent Activity` contains `New finding`.
  - `a scope refusal is recorded`: run active checks against `http://127.0.0.2:8090/` (not in scope); the activity feed then contains `Blocked by scope: http://127.0.0.2:8090/`.
- [ ] **Step 2: Run** `npm run build`, then `npx vitest run --config testcase/e2e/vitest.config.ts testcase/e2e/monitor.e2e.ts`. Expected: 4 tests PASS, no renderer page errors; screenshots under `testcase/results/screenshots/monitor-*.png`.
- [ ] **Step 3: Run the existing e2e** `npx vitest run --config testcase/e2e/vitest.config.ts` to confirm `rules-408` and `gui` specs still pass.
- [ ] **Step 4: Commit**
  ```bash
  git add testcase/e2e/monitor.e2e.ts
  git commit -m "test(monitor): GUI e2e for Exposure Monitor with a local server"
  ```

### Task 7: Docs

**Files:**
- Modify: `docs/034_threat-monitor.md` (keep the filename so links keep working; retitle to "034 — Exposure Monitor (dulu Threat Monitor)"; rewrite Status, Tujuan, Cara kerja, File terkait, Cara pakai, Batasan, Checklist)
- Modify: `docs/000_index.md:54` (status ⚪ → ✅, description), `docs/030_operations.md` (rows at lines 22, 99, 109), `docs/001_ringkasan-proyek.md:16`

- [ ] **Step 1: Rewrite `034`** in Indonesian: sumber data (tabel dari Spec), isi halaman, pesan event persis seperti di Global Constraints, batas 200 event dan hanya di memori, dan **batasan jujur**: bukan IDS, tidak melihat serangan ke komputer atau jaringanmu; sumber telemetri host (Windows Event Log, IDS) tidak termasuk.
- [ ] **Step 2: Update the other three docs** to the new name and status. All docs are CRLF: edit through a script that normalizes to `\n`, applies the change, and writes back `\r\n`; verify `LF-only lines: 0`.
- [ ] **Step 3: Verify:** `grep -rn "Threat Monitor" docs src README.md` shows only intentional mentions (the "dulu Threat Monitor" note).
- [ ] **Step 4: Commit**
  ```bash
  git add docs/034_threat-monitor.md docs/000_index.md docs/030_operations.md docs/001_ringkasan-proyek.md
  git commit -m "docs: Exposure Monitor replaces the simulated Threat Monitor"
  ```

---

## Self-review notes

- **Spec coverage:** page rename and content (Task 4), sources (Task 3), buffer and mapping (Tasks 1-2), generator and setting removal (Tasks 4-5), Dashboard (Task 5), empty states (Tasks 4, 6), docs (Task 7). KEV line uses the existing `KEV_COUNT`, `KEV_CATALOG_VERSION`.
- **Type consistency:** `ActivityDraft` is produced by `eventFromFinding` and consumed by `pushActivity`; `noteScopeBlock` and `inScopeOrNote` signatures match their callers in Task 3.
- **Proportion:** the plan lists signatures, test names with assertions, and exact strings; no function bodies.

## Recommendation for execution

**Native** is the better fit: seven small tasks that share interfaces from Tasks 1-2, so passing names between fresh subagents adds cost without adding safety; one independent review of the whole branch at the end is enough. Choose subagent-driven only if you want a review gate after every task.

---
**Skipped / risks:** the proxy hold event relies on `HeldRequest.method` and `HeldRequest.host` (verified in `src/shared/proxy.ts`). The activity feed is lost on restart by design. The KEV work this plan builds on is still uncommitted on `feat/kev-cve-tagging`; Task 3's commit must not sweep it in. Firewall and the Dashboard host cards still use mock data and are untouched. No instance of the new page has been run yet.
