#!/usr/bin/env node
// Runs on `npm install` in a clone and on git installs (npx github:relbns/cognito-local).
const { execSync } = require("node:child_process");
const fs = require("node:fs");

if (fs.existsSync(".git")) {
  try {
    require("husky").install();
  } catch (e) {
    console.warn(`husky: ${e.message}`);
  }
}

if (process.env.COGNITO_LOCAL_SKIP_BUILD !== "1") {
  execSync("npm run build", { stdio: "inherit" });
}
