import React from 'react'
import { NavLink } from 'react-router-dom'
import Crest from './Crest'
import {
  IconDashboard,
  IconScan,
  IconBug,
  IconRadar,
  IconFirewall,
  IconReport,
  IconSettings,
  IconTarget,
  IconRepeat,
  IconCrosshair,
  IconCode,
  IconColumns,
  IconSequence,
  IconGlobe
} from './icons'

const NAV = [
  { to: '/', label: 'Dashboard', icon: IconDashboard, end: true, group: 'Overview' },

  { to: '/web/target', label: 'Target / Site Map', icon: IconTarget, group: 'Web Security Suite' },
  { to: '/web/proxy', label: 'Proxy', icon: IconGlobe, group: 'Web Security Suite' },
  { to: '/web/repeater', label: 'Repeater', icon: IconRepeat, group: 'Web Security Suite' },
  { to: '/web/intruder', label: 'Intruder', icon: IconCrosshair, group: 'Web Security Suite' },
  { to: '/web/sequencer', label: 'Sequencer', icon: IconSequence, group: 'Web Security Suite' },
  { to: '/web/decoder', label: 'Decoder', icon: IconCode, group: 'Web Security Suite' },
  { to: '/web/comparer', label: 'Comparer', icon: IconColumns, group: 'Web Security Suite' },

  { to: '/scanner', label: 'Network Scanner', icon: IconScan, group: 'Operations' },
  { to: '/vulnerabilities', label: 'Vulnerabilities', icon: IconBug, group: 'Operations' },
  { to: '/threats', label: 'Threat Monitor', icon: IconRadar, group: 'Operations' },
  { to: '/firewall', label: 'Firewall Rules', icon: IconFirewall, group: 'Operations' },

  { to: '/reports', label: 'Reports', icon: IconReport, group: 'Analysis' },
  { to: '/settings', label: 'Settings', icon: IconSettings, group: 'System' }
]

export default function Sidebar() {
  let lastGroup = ''
  const appVersion = '1.0.0'
  const electron = typeof window !== 'undefined' && window.ruy ? window.ruy.versions.electron : '—'

  return (
    <aside className="sidebar">
      <div className="brand">
        <Crest className="crest" size={38} />
        <div className="brand-text">
          <span className="brand-name">INTERU</span>
          <span className="brand-sub">Cyber Operations</span>
        </div>
      </div>

      <nav className="nav">
        {NAV.map((item) => {
          const showGroup = item.group !== lastGroup
          lastGroup = item.group
          const Icon = item.icon
          return (
            <React.Fragment key={item.to}>
              {showGroup && <div className="nav-group-label">{item.group}</div>}
              <NavLink
                to={item.to}
                end={item.end}
                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
              >
                <Icon />
                <span>{item.label}</span>
              </NavLink>
            </React.Fragment>
          )
        })}
      </nav>

      <div className="sidebar-foot">
        <div style={{ letterSpacing: '0.14em', color: 'var(--silver-300)', fontWeight: 600 }}>RUY CYBERSECURITY TEAM</div>
        <div>Interu <span className="ver">v{appVersion}</span> · Electron <span className="ver">{electron}</span></div>
      </div>
    </aside>
  )
}
