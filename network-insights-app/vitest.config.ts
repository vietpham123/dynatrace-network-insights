import { defineConfig } from "vitest/config";

// Unit tests cover the PURE layer only — ui/app/lib/metrics.ts and providers.ts, which import
// nothing. Anything touching @dynatrace-sdk needs a browser runtime and is out of scope here;
// keeping that boundary is what lets `npm test` stay a fast, dependency-free gate.
export default defineConfig({
  test: { include: ["ui/app/**/*.test.ts"], environment: "node" },
});
