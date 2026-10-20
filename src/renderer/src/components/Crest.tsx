import React from 'react'

// The RUY crest: a geometric crown over a shield, rendered in silver and
// midnight blue on obsidian. The exact same geometry is used to generate the
// Windows application icon (see scripts/generate-icons.mjs), so the in-app
// brand mark and the desktop/installer icon stay identical.
export default function Crest({ size = 40, className }: { size?: number; className?: string }) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label="RUY crest"
    >
      <defs>
        <linearGradient id="ruyShield" x1="32" y1="6" x2="32" y2="60" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#1b3a6b" />
          <stop offset="1" stopColor="#0a1830" />
        </linearGradient>
        <linearGradient id="ruySilver" x1="16" y1="10" x2="48" y2="30" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#f3f6fb" />
          <stop offset="1" stopColor="#8d99ad" />
        </linearGradient>
      </defs>

      {/* shield */}
      <path
        d="M32 7 54 14v16c0 14-9.5 22.5-22 27C19.5 52.5 10 44 10 30V14L32 7Z"
        fill="url(#ruyShield)"
        stroke="url(#ruySilver)"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      {/* inner bevel line */}
      <path
        d="M32 12 49 17.5V30c0 11.3-7.4 18.4-17 22.2C22.4 48.4 15 41.3 15 30V17.5L32 12Z"
        fill="none"
        stroke="#3765b8"
        strokeOpacity="0.5"
        strokeWidth="1"
        strokeLinejoin="round"
      />
      {/* crown */}
      <path
        d="M21 32 19 21l6.5 5L32 18l6.5 8 6.5-5-2 11H21Z"
        fill="url(#ruySilver)"
        stroke="#f3f6fb"
        strokeWidth="1"
        strokeLinejoin="round"
      />
      <path d="M20.5 35.5h23" stroke="url(#ruySilver)" strokeWidth="2.4" strokeLinecap="round" />
      {/* crown gems */}
      <circle cx="25.5" cy="26" r="1.5" fill="#12284f" />
      <circle cx="32" cy="18" r="1.6" fill="#244b8f" />
      <circle cx="38.5" cy="26" r="1.5" fill="#12284f" />
    </svg>
  )
}
