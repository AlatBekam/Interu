import React, { useEffect, useRef, useState } from 'react'
import TopBar from '../components/TopBar'
import { Panel, Stat, Disclaimer } from '../components/ui'
import { IconPlay, IconStop, IconRadar, IconShieldAlert } from '../components/icons'
import { ThreatEvent, makeRng, generateEvent, seedEvents } from '../data/mock'
import { useSettings } from '../store/store'

export default function ThreatMonitor() {
  const [settings] = useSettings()
  const [events, setEvents] = useState<ThreatEvent[]>(() => seedEvents(14).reverse())
  const [running, setRunning] = useState(settings.liveFeed)
  const rng = useRef(makeRng(Date.now() & 0xffff))
  const timer = useRef<number | null>(null)

  const stop = () => {
    if (timer.current) window.clearInterval(timer.current)
    timer.current = null
  }

  useEffect(() => {
    if (running) {
      timer.current = window.setInterval(() => {
        setEvents((prev) => [generateEvent(rng.current), ...prev].slice(0, 200))
      }, 2600)
    }
    return () => stop()
  }, [running])

  const counts = {
    crit: events.filter((e) => e.level === 'crit').length,
    warn: events.filter((e) => e.level === 'warn').length,
    blocked: events.filter((e) => e.level === 'ok').length
  }

  return (
    <>
      <TopBar title="Threat Monitor" sub="Simulated intrusion & anomaly feed" />
      <div className="content page">
        <Disclaimer>
          The event stream below is <strong>synthetically generated</strong> by a local model. No intrusion
          detection, packet capture, or interception is taking place. Sources and signatures are fictional.
        </Disclaimer>

        <div className="grid grid-4 mt-16">
          <Stat label="Feed Status" value={running ? 'Live' : 'Paused'} meta={running ? 'generating events' : 'stream halted'} icon={<IconRadar />} trend={running ? 'up' : undefined} />
          <Stat label="Critical Alerts" value={counts.crit} meta="this session" icon={<IconShieldAlert />} />
          <Stat label="Warnings" value={counts.warn} />
          <Stat label="Auto-Mitigated" value={counts.blocked} meta="rules applied" trend="up" />
        </div>

        <Panel
          title="Live Event Stream"
          sub={`${events.length} events buffered · simulated`}
          className="mt-24"
          right={
            running ? (
              <button className="btn btn-danger btn-sm" onClick={() => { stop(); setRunning(false) }}><IconStop />Pause</button>
            ) : (
              <button className="btn btn-primary btn-sm" onClick={() => setRunning(true)}><IconPlay />Resume</button>
            )
          }
        >
          <div className="feed" style={{ maxHeight: 520 }}>
            {events.map((e) => (
              <div className="ln" key={e.id}>
                <span className="ts">{e.ts}</span>
                <span className={`lv ${e.level}`}>{e.level.toUpperCase()}</span>
                <span className="msg">
                  <span className="mono" style={{ color: 'var(--silver-300)' }}>[{e.category}]</span> {e.message}
                </span>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </>
  )
}
