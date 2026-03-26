/**
 * portal/src/assets/WardenLogo.tsx
 * ──────────────────────────────────
 * SVG Shield logo as a React component — avoids external img requests.
 * Supports size and monochrome mode.
 */
interface LogoProps {
  size?:  number
  mono?:  boolean   // single color instead of gradient
  color?: string    // used in mono mode
}

export function WardenLogo({ size = 32, mono = false, color = '#ffffff' }: LogoProps) {
  const gradId = 'wl-grad'

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      aria-label="Shadow Warden logo"
    >
      {!mono && (
        <defs>
          <linearGradient id={gradId} x1="4" y1="2" x2="28" y2="30" gradientUnits="userSpaceOnUse">
            <stop stopColor="#6366f1" />
            <stop offset="1" stopColor="#06b6d4" />
          </linearGradient>
        </defs>
      )}
      {/* Shield */}
      <path
        d="M16 2L4 8v8c0 7.18 5.14 13.9 12 15.5C22.86 29.9 28 23.18 28 16V8L16 2z"
        fill={mono ? color : `url(#${gradId})`}
        opacity={mono ? 1 : 0.9}
      />
      {/* Checkmark */}
      <path
        d="M11 16l3 3 7-7"
        stroke="#ffffff"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}
