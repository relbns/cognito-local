#!/usr/bin/env node

import { runCli } from "../cli";

// Kept for existing setups that run lib/bin/start.js; same as `cognito-emulator start`.
runCli(["start", ...process.argv.slice(2)]).then(
  (code) => process.exit(code),
  (err) => {
    console.error(err);
    process.exit(1);
  },
);
