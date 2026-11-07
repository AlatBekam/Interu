import React from 'react'
import { NavLink } from 'react-router-dom'
import Crest from './Crest'
import {
  IconScan,
  IconBug,
  IconRadar,
  IconSettings,
  IconTarget,
  IconRepeat,
  IconCrosshair,
  IconCode,
  IconColumns,
  IconSequence,
  IconGlobe,
  IconShieldAlert,
  IconSpider,
  IconFlask
} from './icons'

const NAV = [
  { to: '/web/target', label: 'Target / Site Map', icon: IconTarget, group: 'Web Security Suite' },
  { to: '/web/crawler', label: 'Crawler', icon: IconSpider, group: 'Web Security Suite' },
  { to: '/web/activescan', label: 'Active Scan', icon: IconFlask, group: 'Web Security Suite' },
  { to: '/web/proxy', label: 'Proxy', icon: IconGlobe, group: 'Web Security Suite' },
  { to: '/web/repeater', label: 'Repeater', icon: IconRepeat, group: 'Web Security Suite' },
  { to: '/web/intruder', label: 'Intruder', icon: IconCrosshair, group: 'Web Security Suite' },
  { to: '/web/sequencer', label: 'Sequencer', icon: IconSequence, group: 'Web Security Suite' },
  { to: '/web/decoder', label: 'Decoder', icon: IconCode, group: 'Web Security Suite' },
  { to: '/web/comparer', label: 'Comparer', icon: IconColumns, group: 'Web Security Suite' },

  { to: '/scanner', label: 'Network Scanner', icon: IconScan, group: 'Operations' },
  { to: '/vulnerabilities', label: 'Vulnerabilities', icon: IconBug, group: 'Operations' },
  { to: '/threats', label: 'Exposure Monitor', icon: IconRadar, group: 'Operations' },

  { to: '/detection', label: 'Rule Engine', icon: IconShieldAlert, group: 'Detection' },

  { to: '/settings', label: 'Settings', icon: IconSettings, group: 'System' }
]

export default function Sidebar() {
  let lastGroup = ''
  const appVersion = '1.0.0'
  const electron = typeof window !== 'undefined' && window.ruy ? window.ruy.versions.electron : '—'

  return (
    <aside className="sidebar">
      <div className="brand">
        <Crest className="crest" size={28} />
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
        <div className="team">RUY CYBERSECURITY TEAM</div>
        <div>Interu <span className="ver">v{appVersion}</span> · Electron <span className="ver">{electron}</span></div>
      </div>
    </aside>
  )
}
