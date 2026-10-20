import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import NetworkScanner from './pages/NetworkScanner'
import Vulnerabilities from './pages/Vulnerabilities'
import ThreatMonitor from './pages/ThreatMonitor'
import Firewall from './pages/Firewall'
import Reports from './pages/Reports'
import Settings from './pages/Settings'
import Proxy from './pages/web/Proxy'
import Repeater from './pages/web/Repeater'
import Intruder from './pages/web/Intruder'
import Decoder from './pages/web/Decoder'
import Comparer from './pages/web/Comparer'
import Sequencer from './pages/web/Sequencer'
import Target from './pages/web/Target'
import { useSettings, useApplyTheme, useBodyMotionFlag } from './store/store'

export default function App() {
  const [settings] = useSettings()
  useApplyTheme(settings.theme)
  useBodyMotionFlag(settings.reduceMotion)

  return (
    <div className="app-shell">
      <Sidebar />
      <main className="main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          {/* Web Security Suite (Burp-style, simulated) */}
          <Route path="/web/target" element={<Target />} />
          <Route path="/web/proxy" element={<Proxy />} />
          <Route path="/web/repeater" element={<Repeater />} />
          <Route path="/web/intruder" element={<Intruder />} />
          <Route path="/web/sequencer" element={<Sequencer />} />
          <Route path="/web/decoder" element={<Decoder />} />
          <Route path="/web/comparer" element={<Comparer />} />
          {/* Operations */}
          <Route path="/scanner" element={<NetworkScanner />} />
          <Route path="/vulnerabilities" element={<Vulnerabilities />} />
          <Route path="/threats" element={<ThreatMonitor />} />
          <Route path="/firewall" element={<Firewall />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}
