import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SCRIPT = join(__dirname, "../scripts/check-no-vendor-terms.mjs");
const run = (root?: string) =>
  spawnSync(process.execPath, root ? [SCRIPT, root] : [SCRIPT], {
    encoding: "utf8",
  });

describe("vendor-term guard", () => {
  it("finds no vendor-specific terms in the repository", () => {
    const result = run();
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
  });

  it("flags a username shape and a real-country phone number", () => {
    const dir = mkdtempSync(join(tmpdir(), "vendor-terms-"));
    try {
      writeFileSync(
        join(dir, "sample.ts"),
        `const user = "jane@example.test${"<"}->1";\nconst phone = "+97${"2"}500000000";\n`,
      );
      const result = run(dir);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("sample.ts:1:");
      expect(result.stderr).toContain("sample.ts:2:");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
