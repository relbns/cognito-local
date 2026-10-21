# Command line

One program with subcommands, installed as `cognito-emulator` and as the alias `cognito-local`, which
behaves the same. This page uses `cognito-emulator`. Every option has a flag, nothing prompts when stdin
is not a terminal, and `status`, `seed`, `export` and `reset` print JSON with `--json`.

```bash
npx github:relbns/cognito-local start --seed ./cognito-emulator.seed.json
```

## Running it

| How | Command |
|-----|---------|
| From the npm registry (once published) | `npx cognito-emulator start`, or `npm install -g cognito-emulator` |
| From GitHub, no clone | `npx github:relbns/cognito-local start` (npm clones the repo, installs its dev dependencies and builds it once; add `#<branch or sha>` to pin a version) |
| Global command | `npm install -g "$(npm pack github:relbns/cognito-local \| tail -1)"` in an empty directory, then `cognito-emulator start`. A plain `npm install -g github:relbns/cognito-local` fails with npm 10 (`tsc: command not found`: npm builds the git dependency in global mode without its dev dependencies) |
| Project dev dependency | `npm install --save-dev github:relbns/cognito-local`, then `npx cognito-emulator start` |
| From a clone | `npm install` (builds `lib/`), then `node lib/bin/cli.js start`, or `npm run cli -- start` to run the TypeScript source |
| Old entry point | `node lib/bin/start.js` still works and is the same as `cognito-emulator start` |

The npm package is `cognito-emulator`, so it does not clash with upstream's `cognito-local`. It is not
on the npm registry yet; the GitHub commands above work today.

## Commands

| Command | What it does |
|---------|--------------|
| `cognito-emulator [start]` | Runs the emulator. `start` is the default, so a bare `cognito-emulator` behaves like the old start script. Applies `--seed` before listening. |
| `cognito-emulator seed <file>` | Applies a [seed file](seed-files.md). When a server is running for the data directory (or `--url` is given), it goes through that server's admin API (`POST /_admin/api/seed`), so the running process sees the change at once; otherwise it writes the data directory directly. |
| `cognito-emulator export [--out <file>]` | Prints, or writes to `--out`, a seed file that re-creates the current state. Passwords are never exported. With `--out`, `file:` trigger paths are made relative to the output file when they are at most one directory above it. |
| `cognito-emulator reset [--yes] [--all]` | Deletes `<data>/db` (pools, clients, users). `--all` also deletes `config.json`. Refuses while a server is running on the data directory. Asks for confirmation on a terminal; without a terminal it needs `--yes` and exits 2 otherwise. |
| `cognito-emulator status` | Reports whether a server is running for the data directory: URL, pid, admin UI, number of user pools. Exit code 3 when it is not running. |
| `cognito-emulator help`, `--help`, `--version` | Usage and version. |

## Options

| Flag | Environment | Default | Commands |
|------|-------------|---------|----------|
| `--data <dir>` | `COGNITO_LOCAL_DATA_DIR` | `.cognito` | all |
| `--port <n>` | `PORT` | `9229` | start |
| `--host <h>` | `HOST` | `localhost` | start |
| `--seed <file>` | `COGNITO_LOCAL_SEED` | none | start |
| `--admin` / `--no-admin` | `COGNITO_LOCAL_ADMIN_UI` | on | start |
| `--admin-token <t>` | `COGNITO_LOCAL_ADMIN_TOKEN` | none (open) | start: the token the admin UI and its API require. seed, export, status: the token sent to the server, falling back to `AdminUIConfig.Token` in `<data>/config.json` |
| `--url <url>` | | from the data directory | seed, export, status |
| `--out <file>` | | stdout | export |
| `--json` | | off | seed, export, reset, status |
| `--yes`, `-y` | | off | reset |
| `--all` | | off | reset |

A flag wins over the environment, the environment over the built-in default. Values in
`<data>/config.json` (`ServerConfig.port`, `ServerConfig.hostname`, `AdminUIConfig.Enabled`,
`AdminUIConfig.Token`) win over the environment but not over a flag. The token issuer (`TokenConfig.IssuerDomain`) follows the
final host and port unless `config.json` sets it; a wildcard host (`0.0.0.0`, `::`) becomes
`localhost` in the issuer. `TokenConfig.IssuerFromRequest: true` takes the issuer from each
request's `Host` header instead (see [tokens.md](tokens.md#issuer)).

## Data directory

```
.cognito/
  config.json     emulator configuration (unchanged format)
  db/             one JSON file per user pool, plus clients.json
  server.json     written by `start` while it runs: pid, URL, port, admin UI flag
```

`seed`, `export`, `reset` and `status` find a running server through `server.json` (they check the
pid and `GET /health`). A stale file left by a killed process is ignored.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (status: running) |
| 1 | Error, for example an invalid seed or a server already running |
| 2 | Usage error, or a confirmation is needed (`reset` without `--yes` and without a terminal) |
| 3 | `status`: not running |

## Examples

```bash
# Start on another port with a seed and a throwaway data directory
cognito-emulator start --port 9330 --data /tmp/cognito --seed examples/seed.basic.json

# Re-apply after editing the seed; the running server picks it up
cognito-emulator seed examples/seed.basic.json --data /tmp/cognito --json

# Snapshot the current state as a seed file
cognito-emulator export --data /tmp/cognito --out ./cognito-emulator.seed.json

# In a script
cognito-emulator status --data /tmp/cognito --json || echo "not running"
cognito-emulator reset --data /tmp/cognito --yes
```
