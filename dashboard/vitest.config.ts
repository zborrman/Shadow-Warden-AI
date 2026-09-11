import path from "node:path";
import { defineConfig } from "vitest/config";

/**
 * Bootstrap config (plan-85 M-1). Route handlers under `src/app/api/**` run
 * in the Node runtime, not a browser, so `environment: "node"` is correct and
 * needs no jsdom — `NextRequest`/`NextResponse` are plain Node/Web APIs.
 * Component tests will want `environment: "jsdom"`; add those as a separate
 * Vitest "project" (or a per-file `// @vitest-environment jsdom` pragma) when
 * the first component test lands, rather than paying jsdom's cost here.
 */
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"],
      include: ["src/**/*.ts", "src/**/*.tsx"],
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
});
