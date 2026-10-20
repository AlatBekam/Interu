import React from 'react'
import { IconSun, IconMoon } from './icons'
import { useSettings } from '../store/store'

// Light / Dark switch shown in the top-right of every screen.
export default function ThemeToggle() {
  const [settings, patch] = useSettings()
  const theme = settings.theme
  return (
    <div className="theme-toggle" role="group" aria-label="Color theme">
      <button
        className={theme === 'light' ? 'on' : ''}
        onClick={() => patch({ theme: 'light' })}
        title="Light theme"
        aria-pressed={theme === 'light'}
      >
        <IconSun />
        Light
      </button>
      <button
        className={theme === 'dark' ? 'on' : ''}
        onClick={() => patch({ theme: 'dark' })}
        title="Dark theme"
        aria-pressed={theme === 'dark'}
      >
        <IconMoon />
        Dark
      </button>
    </div>
  )
}
