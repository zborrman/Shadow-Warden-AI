import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: {
          0: "#050810",
          1: "#0a0e1a",
          2: "#0d1220",
          3: "#111828",
          4: "#1a2236",
        },
        accent: {
          purple: "#7c3aed",
          blue:   "#2563eb",
          cyan:   "#06b6d4",
          green:  "#10b981",
          yellow: "#f59e0b",
          red:    "#ef4444",
          orange: "#f97316",
        },
        border: "#1e2a42",
      },
      fontFamily: { mono: ["'JetBrains Mono'", "monospace"] },
      animation: {
        pulse2: "pulse 2s cubic-bezier(0.4,0,0.6,1) infinite",
        "fade-in": "fadeIn 0.3s ease",
      },
      keyframes: {
        fadeIn: { from: { opacity: "0", transform: "translateY(4px)" }, to: { opacity: "1", transform: "translateY(0)" } },
      },
    },
  },
  plugins: [],
};

export default config;
