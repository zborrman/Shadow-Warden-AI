/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{js,ts,jsx,tsx,mdx}'],
  theme: {
    extend: {
      colors: {
        // Dark background palette — matches landing page
        dark: {
          950: '#020509',
          900: '#050a13',
          800: '#0b1220',
          700: '#111b2e',
          600: '#1a2540',
        },
        // Brand accent — sky/cyan
        brand: {
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
        },
        // Secondary accent — violet
        violet: {
          300: '#c4b5fd',
          400: '#818cf8',
          500: '#6366f1',
        },
        // Risk level colours
        risk: {
          low:    '#22c55e',   // green-500
          medium: '#f59e0b',   // amber-500
          high:   '#ef4444',   // red-500
          block:  '#dc2626',   // red-600
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'monospace'],
      },
      backgroundImage: {
        'brand-gradient': 'linear-gradient(135deg, #38bdf8, #818cf8)',
        'card-gradient':  'linear-gradient(135deg, rgba(56,189,248,0.05), rgba(129,140,248,0.05))',
      },
    },
  },
  plugins: [],
}
