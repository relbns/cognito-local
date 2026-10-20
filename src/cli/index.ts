import fs from "node:fs";
import type * as http from "node:http";
import * as https from "node:https";
import path from "node:path";
import * as readline from "node:readline";
import { parseArgs } from "node:util";
import Pino from "pino";
import PinoPretty from "pino-pretty";
import {
  applySeed,
  exportSeed,
  formatSeedResult,
  loadSeedFile,
  PASSWORDS_NOT_EXPORTED,
  relativizeSeedFileTargets,
  type SeedChange,
  type SeedFile,
  SeedValidationError,
  summarizeSeedResult,
} from "../seed";
import {
  createDefaultServer,
  createDefaultServices,
  resolveDataDirectory,
} from "../server/defaults";

export const EXIT = {
  OK: 0,
  ERROR: 1,
  USAGE: 2,
  NOT_RUNNING: 3,
} as const;

export const RUNTIME_FILE = "server.json";

export interface CliIO {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  isTTY: boolean;
  prompt: (question: string) => Promise<string>;
  env: NodeJS.ProcessEnv;
}

export const processIO = (): CliIO => ({
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
  isTTY: !!process.stdin.isTTY && !!process.stdout.isTTY,
  prompt: (question) =>
    new Promise((resolve) => {
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stderr,
      });
      rl.question(question, (answer) => {
        rl.close();
        resolve(answer);
      });
    }),
  env: process.env,
});

export interface RuntimeInfo {
  pid: number;
  url: string;
  hostname: string;
  port: number;
  adminUi: boolean;
  startedAt: string;
  dataDirectory: string;
}

class UsageError extends Error {}

const USAGE = `cognito-local: a local Amazon Cognito User Pools emulator

Usage:
  cognito-local [start] [--port <n>] [--host <h>] [--data <dir>] [--seed <file>] [--admin | --no-admin]
  cognito-local seed <file> [--data <dir>] [--url <url>] [--json]
  cognito-local export [--out <file>] [--data <dir>] [--url <url>] [--json]
  cognito-local reset [--yes] [--all] [--data <dir>] [--json]
  cognito-local status [--data <dir>] [--url <url>] [--json]
  cognito-local help [command] | --help | --version

Commands:
  start    Run the emulator (default). Applies --seed before listening.
  seed     Apply a seed file. Goes through the running server's admin API when one serves
           the data directory, otherwise writes the data directory directly.
  export   Print or write a seed file that re-creates the current state (no passwords).
  reset    Delete the data directory's db/ (and config.json with --all). Needs --yes when
           stdin is not a terminal; refuses while a server is running.
  status   Report whether a server is running for the data directory. Exit code 3 if not.

Options:
  --data <dir>   Data directory holding config.json and db/ (env COGNITO_LOCAL_DATA_DIR, default .cognito)
  --port <n>     Port (env PORT, default 9229)
  --host <h>     Host to bind (env HOST, default localhost)
  --seed <file>  Seed file applied at startup (env COGNITO_LOCAL_SEED)
  --admin        Enable the admin UI at /_admin (default; env COGNITO_LOCAL_ADMIN_UI)
  --no-admin     Disable the admin UI and its API
  --url <url>    Talk to a server at this URL instead of looking it up from the data directory
  --json         Machine-readable output
  --yes          Confirm a destructive command without prompting

Exit codes: 0 ok, 1 error, 2 usage error or confirmation needed, 3 not running (status).
`;

const OPTIONS = {
  port: { type: "string" },
  host: { type: "string" },
  data: { type: "string" },
  seed: { type: "string" },
  admin: { type: "boolean" },
  "no-admin": { type: "boolean" },
  url: { type: "string" },
  out: { type: "string" },
  json: { type: "boolean" },
  yes: { type: "boolean", short: "y" },
  all: { type: "boolean" },
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
} as const;

type Flags = {
  [K in keyof typeof OPTIONS]?: (typeof OPTIONS)[K]["type"] extends "boolean"
    ? boolean
    : string;
};

const COMMANDS = ["start", "seed", "export", "reset", "status", "help"];

const COMMAND_FLAGS: Record<string, (keyof typeof OPTIONS)[]> = {
  start: ["port", "host", "data", "seed", "admin", "no-admin"],
  seed: ["data", "url", "json"],
  export: ["out", "data", "url", "json"],
  reset: ["yes", "all", "data", "json"],
  status: ["data", "url", "json"],
  help: [],
};

export const parseCli = (argv: readonly string[]) => {
  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs({
      args: [...argv],
      options: OPTIONS,
      allowPositionals: true,
      strict: true,
    });
  } catch (e) {
    throw new UsageError((e as Error).message);
  }
  const flags = parsed.values as Flags;
  const positionals = [...parsed.positionals];
  const command =
    positionals.length && COMMANDS.includes(positionals[0])
      ? (positionals.shift() as string)
      : "start";
  if (!flags.help && !flags.version) {
    for (const key of Object.keys(flags) as (keyof typeof OPTIONS)[]) {
      if (!COMMAND_FLAGS[command].includes(key)) {
        throw new UsageError(`--${key} is not an option of "${command}"`);
      }
    }
  }
  if (flags.admin && flags["no-admin"]) {
    throw new UsageError("--admin and --no-admin are mutually exclusive");
  }
  const expected = command === "seed" ? 1 : command === "help" ? 1 : 0;
  if (positionals.length > expected) {
    throw new UsageError(`unexpected argument "${positionals[expected]}"`);
  }
  if (command === "seed" && !positionals.length && !flags.help) {
    throw new UsageError("seed needs a file: cognito-local seed <file>");
  }
  return { command, flags, positionals };
};

const parsePort = (value: string | undefined): number | undefined => {
  if (value === undefined) return undefined;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new UsageError(`--port must be an integer between 0 and 65535`);
  }
  return port;
};

const readPackageVersion = (): string => {
  try {
    return JSON.parse(
      fs.readFileSync(path.join(__dirname, "../../package.json"), "utf8"),
    ).version;
  } catch {
    return "unknown";
  }
};

const runtimeFile = (dataDirectory: string) =>
  path.join(dataDirectory, RUNTIME_FILE);

const pidAlive = (pid: number) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
};

const healthy = async (url: string): Promise<boolean> => {
  try {
    const res = await fetch(`${url}/health`, {
      signal: AbortSignal.timeout(2000),
    });
    return res.ok;
  } catch {
    return false;
  }
};

export const readRuntimeInfo = (dataDirectory: string): RuntimeInfo | null => {
  try {
    return JSON.parse(fs.readFileSync(runtimeFile(dataDirectory), "utf8"));
  } catch {
    return null;
  }
};

export interface RunningServer {
  url: string;
  pid?: number;
  adminUi?: boolean;
}

export const findRunningServer = async (
  dataDirectory: string,
  url?: string,
): Promise<RunningServer | null> => {
  if (url) {
    const base = url.replace(/\/+$/, "");
    return (await healthy(base)) ? { url: base } : null;
  }
  const info = readRuntimeInfo(dataDirectory);
  if (!info || !pidAlive(info.pid)) return null;
  return (await healthy(info.url))
    ? { url: info.url, pid: info.pid, adminUi: info.adminUi }
    : null;
};

const connectHost = (hostname: string | undefined) =>
  !hostname || hostname === "0.0.0.0" || hostname === "::"
    ? "localhost"
    : hostname.includes(":")
      ? `[${hostname}]`
      : hostname;

const countPools = (dataDirectory: string): number => {
  const db = path.join(dataDirectory, "db");
  if (!fs.existsSync(db)) return 0;
  return fs
    .readdirSync(db)
    .filter((f) => f.endsWith(".json") && f !== "clients.json").length;
};

const quietLogger = () =>
  Pino(
    { level: process.env.DEBUG ? "debug" : "warn" },
    Pino.destination(2),
  ) as unknown as Pino.Logger;

const adminApi = async (
  server: RunningServer,
  pathname: string,
  init?: RequestInit,
): Promise<{ status: number; body: Record<string, unknown> }> => {
  const res = await fetch(`${server.url}/_admin${pathname}`, init);
  const text = await res.text();
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(text);
  } catch {
    body = { error: text };
  }
  if (res.status === 404 && !("changes" in body) && !("UserPools" in body)) {
    throw new Error(
      `the server at ${server.url} has the admin UI disabled; restart it with --admin, or stop it to work on the data directory directly`,
    );
  }
  return { status: res.status, body };
};

const json = (io: CliIO, value: unknown) =>
  io.stdout(`${JSON.stringify(value, null, 2)}\n`);

async function commandStart(io: CliIO, flags: Flags): Promise<number> {
  const dataDirectory = resolveDataDirectory(flags.data);
  const running = await findRunningServer(dataDirectory);
  if (running) {
    io.stderr(
      `cognito-local is already serving ${dataDirectory} at ${running.url} (pid ${running.pid}); stop it first.\n`,
    );
    return EXIT.ERROR;
  }

  const logger = Pino(
    { level: process.env.DEBUG ? "debug" : "info" },
    PinoPretty({
      colorize: true,
      ignore: "pid,name,hostname",
      singleLine: true,
      messageFormat: (log, messageKey) =>
        `${log.reqId ?? "NONE"} ${log.target ?? "NONE"} ${log[messageKey]}`,
    }),
  );

  const server = await createDefaultServer(logger, {
    dataDirectory,
    port: parsePort(flags.port),
    hostname: flags.host,
    adminUi: flags["no-admin"] ? false : flags.admin ? true : undefined,
    seedFile: flags.seed,
  });
  const httpServer: http.Server | https.Server = await server.start();
  const address = httpServer.address();
  if (!address || typeof address === "string") {
    throw new Error("Server started without a TCP address");
  }
  const proto = httpServer instanceof https.Server ? "https" : "http";
  const url = `${proto}://${connectHost(server.services.config.ServerConfig.hostname ?? address.address)}:${address.port}`;

  const info: RuntimeInfo = {
    pid: process.pid,
    url,
    hostname: address.address,
    port: address.port,
    adminUi: !!server.adminUiPath,
    startedAt: new Date().toISOString(),
    dataDirectory: path.resolve(dataDirectory),
  };
  fs.writeFileSync(runtimeFile(dataDirectory), JSON.stringify(info, null, 2));

  logger.info(`Cognito Local running on ${url}`);
  if (server.adminUiPath) {
    logger.info(
      `Admin UI on ${url}${server.adminUiPath} (no authentication, local development only)`,
    );
  }
  logger.info(`Data directory ${info.dataDirectory}`);

  return new Promise<number>((resolve) => {
    const stop = () => {
      const current = readRuntimeInfo(dataDirectory);
      if (current?.pid === process.pid) {
        fs.rmSync(runtimeFile(dataDirectory), { force: true });
      }
      httpServer.close(() => resolve(EXIT.OK));
      httpServer.closeAllConnections?.();
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
}

const changeSummary = (changes: SeedChange[]) =>
  summarizeSeedResult({ changes });

async function commandSeed(
  io: CliIO,
  flags: Flags,
  file: string,
): Promise<number> {
  const dataDirectory = resolveDataDirectory(flags.data);
  const source = path.resolve(file);
  const seed = loadSeedFile(source);
  const running = await findRunningServer(dataDirectory, flags.url);

  let changes: SeedChange[];
  let lines: string[];
  if (running) {
    const { status, body } = await adminApi(
      running,
      `/api/seed?${new URLSearchParams({ source })}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(seed),
      },
    );
    if (status !== 200) {
      throw new Error(String(body.error ?? `HTTP ${status}`));
    }
    changes = body.changes as SeedChange[];
    lines = body.lines as string[];
  } else {
    if (flags.url) {
      throw new Error(`no cognito-local server answers at ${flags.url}`);
    }
    const { services } = await createDefaultServices(quietLogger(), {
      dataDirectory,
    });
    const result = await applySeed(
      { logger: quietLogger() },
      services,
      seed,
      source,
    );
    changes = result.changes;
    lines = formatSeedResult(result);
  }

  const summary = changeSummary(changes);
  if (flags.json) {
    json(io, {
      mode: running ? "server" : "data-directory",
      url: running?.url,
      dataDirectory: path.resolve(dataDirectory),
      seed: source,
      summary,
      changes,
    });
  } else {
    for (const line of lines) io.stdout(`${line}\n`);
    io.stdout(
      `Seed ${source} applied ${running ? `through ${running.url}` : `to ${dataDirectory}`}: ${summary.created} created, ${summary.updated} updated, ${summary.unchanged} unchanged.\n`,
    );
  }
  return EXIT.OK;
}

async function commandExport(io: CliIO, flags: Flags): Promise<number> {
  const dataDirectory = resolveDataDirectory(flags.data);
  const running = await findRunningServer(dataDirectory, flags.url);
  let seed: SeedFile;
  if (running) {
    const { status, body } = await adminApi(running, "/api/export");
    if (status !== 200) throw new Error(String(body.error ?? `HTTP ${status}`));
    seed = body as unknown as SeedFile;
  } else if (flags.url) {
    throw new Error(`no cognito-local server answers at ${flags.url}`);
  } else if (!fs.existsSync(path.join(dataDirectory, "db"))) {
    seed = {
      $comment: `Exported by cognito-local on ${new Date().toISOString()}. ${PASSWORDS_NOT_EXPORTED}`,
      Version: 1,
      UserPools: [],
    };
  } else {
    const { services } = await createDefaultServices(quietLogger(), {
      dataDirectory,
    });
    seed = await exportSeed({ logger: quietLogger() }, services);
  }

  const pools = seed.UserPools.length;
  const users = seed.UserPools.reduce((n, p) => n + (p.Users?.length ?? 0), 0);
  if (!flags.out) {
    json(io, seed);
    return EXIT.OK;
  }
  const out = path.resolve(flags.out);
  const portable = relativizeSeedFileTargets(seed, path.dirname(out));
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, `${JSON.stringify(portable, null, 2)}\n`);
  if (flags.json) {
    json(io, {
      out,
      mode: running ? "server" : "data-directory",
      pools,
      users,
      note: PASSWORDS_NOT_EXPORTED,
    });
  } else {
    io.stdout(
      `Exported ${pools} user pool(s) and ${users} user(s) to ${out}.\n${PASSWORDS_NOT_EXPORTED}\n`,
    );
  }
  return EXIT.OK;
}

async function commandReset(io: CliIO, flags: Flags): Promise<number> {
  const dataDirectory = resolveDataDirectory(flags.data);
  const running = await findRunningServer(dataDirectory);
  if (running) {
    io.stderr(
      `cognito-local is running on ${dataDirectory} at ${running.url} (pid ${running.pid}); stop it before reset.\n`,
    );
    return EXIT.ERROR;
  }
  const targets = [
    path.join(dataDirectory, "db"),
    ...(flags.all
      ? [path.join(dataDirectory, "config.json"), runtimeFile(dataDirectory)]
      : []),
  ].filter((p) => fs.existsSync(p));

  if (!targets.length) {
    if (flags.json) json(io, { reset: false, removed: [], dataDirectory });
    else io.stdout(`Nothing to reset in ${dataDirectory}.\n`);
    return EXIT.OK;
  }

  if (!flags.yes) {
    if (!io.isTTY) {
      io.stderr(
        `reset deletes ${targets.join(", ")}. Re-run with --yes to confirm (stdin is not a terminal, so cognito-local will not prompt).\n`,
      );
      return EXIT.USAGE;
    }
    const answer = await io.prompt(`Delete ${targets.join(", ")}? [y/N] `);
    if (!/^y(es)?$/i.test(answer.trim())) {
      io.stderr("Reset cancelled.\n");
      return EXIT.USAGE;
    }
  }

  for (const target of targets) {
    fs.rmSync(target, { recursive: true, force: true });
  }
  if (flags.json) json(io, { reset: true, removed: targets, dataDirectory });
  else io.stdout(`Removed ${targets.join(", ")}.\n`);
  return EXIT.OK;
}

async function commandStatus(io: CliIO, flags: Flags): Promise<number> {
  const dataDirectory = resolveDataDirectory(flags.data);
  const running = await findRunningServer(dataDirectory, flags.url);
  let pools: number | undefined;
  let adminUi = running?.adminUi;
  if (running) {
    try {
      const res = await fetch(`${running.url}/_admin/api/status`, {
        signal: AbortSignal.timeout(2000),
      });
      if (res.ok) {
        pools = ((await res.json()) as { pools: number }).pools;
        adminUi = true;
      } else if (res.status === 404) {
        adminUi = false;
      }
    } catch {
      pools = undefined;
    }
  }
  if (pools === undefined && !flags.url) pools = countPools(dataDirectory);

  const status = {
    running: !!running,
    url: running?.url,
    pid: running?.pid,
    adminUi,
    adminUrl: running && adminUi ? `${running.url}/_admin` : undefined,
    pools,
    dataDirectory: flags.url ? undefined : path.resolve(dataDirectory),
    version: readPackageVersion(),
  };
  if (flags.json) {
    json(io, status);
  } else if (running) {
    io.stdout(
      `cognito-local is running at ${running.url}${running.pid ? ` (pid ${running.pid})` : ""}${pools === undefined ? "" : `, ${pools} user pool(s)`}${status.adminUrl ? `, admin UI ${status.adminUrl}` : ""}.\n`,
    );
  } else {
    io.stdout(
      `cognito-local is not running${flags.url ? ` at ${flags.url}` : ` for ${dataDirectory}`}${pools === undefined ? "" : ` (${pools} user pool(s) on disk)`}.\n`,
    );
  }
  return running ? EXIT.OK : EXIT.NOT_RUNNING;
}

export const runCli = async (
  argv: readonly string[],
  io: CliIO = processIO(),
): Promise<number> => {
  let parsed: ReturnType<typeof parseCli>;
  try {
    parsed = parseCli(argv);
  } catch (e) {
    io.stderr(`${(e as Error).message}\n\n${USAGE}`);
    return EXIT.USAGE;
  }
  const { command, flags, positionals } = parsed;
  if (flags.version) {
    io.stdout(`${readPackageVersion()}\n`);
    return EXIT.OK;
  }
  if (flags.help || command === "help") {
    io.stdout(USAGE);
    return EXIT.OK;
  }

  try {
    switch (command) {
      case "seed":
        return await commandSeed(io, flags, positionals[0]);
      case "export":
        return await commandExport(io, flags);
      case "reset":
        return await commandReset(io, flags);
      case "status":
        return await commandStatus(io, flags);
      default:
        return await commandStart(io, flags);
    }
  } catch (e) {
    if (flags.json) {
      json(io, {
        error: (e as Error).message,
        ...(e instanceof SeedValidationError ? { issues: e.issues } : {}),
      });
    } else {
      io.stderr(`${(e as Error)?.message ?? e}\n`);
    }
    return EXIT.ERROR;
  }
};
