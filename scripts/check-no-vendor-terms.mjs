#!/usr/bin/env node
// Fails when a file names a specific product, tenant or data shape; examples must stay generic AWS-style.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

// Organization and tenant names, base64-encoded so this list does not spell them out in the repo.
const ENCODED_NAMES = [
  "XGJiZXdpdGg=",
  "XGJzdXBlcmNv",
  "XGJjb2luZ1xi",
  "XGJ3aXRoYmNcYg==",
  "XGJ0YW1hcmFjXGI=",
  "XGJ3ZWhvXGI=",
  "XGJmaXNoZXJzXGI=",
];

export const FORBIDDEN = [
  ...ENCODED_NAMES.map((encoded) => ({
    pattern: new RegExp(Buffer.from(encoded, "base64").toString(), "i"),
    reason: "organization or tenant name",
  })),
  { pattern: /custom:context\b/, reason: "application-specific attribute" },
  { pattern: /<->/, reason: "application-specific username shape" },
  { pattern: /\botp_/i, reason: "application-specific username shape" },
  { pattern: /\+972/, reason: "real-country phone number, use +1555555xxxx" },
];

const SKIP_DIRS = new Set([
  ".git",
  ".worktrees",
  ".cognito",
  "node_modules",
  "lib",
  "coverage",
]);
const SKIP_FILES = new Set(["CHANGELOG.md", "package-lock.json", "yarn.lock"]);
const SELF = fileURLToPath(import.meta.url);

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) yield* walk(path);
    } else if (entry.isFile() && !SKIP_FILES.has(entry.name) && path !== SELF) {
      yield path;
    }
  }
}

export function findVendorTerms(root) {
  const findings = [];
  for (const file of walk(root)) {
    const buffer = readFileSync(file);
    if (buffer.includes(0)) continue;
    const lines = buffer.toString("utf8").split("\n");
    lines.forEach((line, index) => {
      for (const { pattern, reason } of FORBIDDEN) {
        if (pattern.test(line)) {
          findings.push({
            file: relative(root, file),
            line: index + 1,
            reason,
          });
        }
      }
    });
  }
  return findings;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const root = process.argv[2] ?? join(fileURLToPath(import.meta.url), "../..");
  const findings = findVendorTerms(root);
  for (const f of findings) {
    console.error(`${f.file}:${f.line}: ${f.reason}`);
  }
  if (findings.length > 0) {
    console.error(
      `\n${findings.length} vendor-specific term(s) found. Use generic examples (example.test, +15555550100, ExampleOIDC).`,
    );
    process.exit(1);
  }
  console.log("no vendor-specific terms found");
}
