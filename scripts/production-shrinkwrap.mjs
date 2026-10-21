import { readFileSync, rmSync, writeFileSync } from "node:fs";

const SHRINKWRAP = "npm-shrinkwrap.json";

export function productionShrinkwrap(lock) {
  const packages = {};
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (entry.dev) continue;
    packages[path] = entry;
  }
  return { ...lock, packages };
}

if (process.argv[2] === "write") {
  const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
  writeFileSync(SHRINKWRAP, `${JSON.stringify(productionShrinkwrap(lock), null, 2)}\n`);
} else if (process.argv[2] === "remove") {
  rmSync(SHRINKWRAP, { force: true });
} else {
  console.error("usage: production-shrinkwrap.mjs write|remove");
  process.exit(1);
}
