import React, { useEffect, useState } from 'react'
import ThemeToggle from './ThemeToggle'

export default function TopBar({ title, sub }: { title: string; sub?: string }) {
  const [now, setNow] = useState(() => new Date())

  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  return (
    <header className="topbar">
      <div>
        <div className="page-title">{title}</div>
        {sub && <div className="page-sub">{sub}</div>}
      </div>
      <div className="topbar-spacer" />
      <ThemeToggle />
      <div className="sim-badge" title="All activity in this application is simulated demo data.">
        <span className="dot" />
        Simulation Mode
      </div>
      <div className="clock">
        <div>{now.toLocaleTimeString('en-GB', { hour12: false })}</div>
        <div className="c-date">{now.toLocaleDateString('en-GB', { weekday: 'short', day: '2-digit', month: 'short', year: 'numeric' })}</div>
      </div>
    </header>
  )
}
