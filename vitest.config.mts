import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    setupFiles: ["./setupTests.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts", "src/**/__tests__/**", "src/bin/**"],
      reporter: ["text-summary", "html", "json-summary"],
      thresholds: {
        lines: 93,
        statements: 93,
        branches: 85,
        functions: 97,
      },
    },
  },
});
