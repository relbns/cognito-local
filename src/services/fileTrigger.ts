import { randomUUID } from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const FILE_TRIGGER_PREFIX = "file:";
export const DEFAULT_FILE_TRIGGER_TIMEOUT_MS = 5000;

export interface FileTriggerTarget {
  file: string;
  exportName: string;
}

export const isFileTarget = (value: unknown): value is string =>
  typeof value === "string" && value.startsWith(FILE_TRIGGER_PREFIX);

export const parseFileTarget = (
  value: string,
  baseDir: string = process.cwd(),
): FileTriggerTarget => {
  if (!isFileTarget(value)) {
    throw new Error(`"${value}" is not a file: trigger target`);
  }
  const rest = value.slice(FILE_TRIGGER_PREFIX.length);
  const hash = rest.lastIndexOf("#");
  const location = hash >= 0 ? rest.slice(0, hash) : rest;
  const exportName = (hash >= 0 ? rest.slice(hash + 1) : "") || "handler";
  if (!location) {
    throw new Error(`"${value}" has no file path`);
  }
  const file = location.startsWith("//")
    ? fileURLToPath(`file:${location}`)
    : path.resolve(baseDir, location);
  return { file, exportName };
};

export const formatFileTarget = (target: FileTriggerTarget): string =>
  `${FILE_TRIGGER_PREFIX}${target.file}${target.exportName === "handler" ? "" : `#${target.exportName}`}`;

export const resolveFileTarget = (value: string, baseDir: string): string =>
  formatFileTarget(parseFileTarget(value, baseDir));

export class FileTriggerError extends Error {
  public constructor(
    message: string,
    public readonly kind: "load" | "handler" | "timeout" | "response",
  ) {
    super(message);
  }
}

type Handler = (
  event: unknown,
  context: Record<string, unknown>,
  callback: (err?: unknown, result?: unknown) => void,
) => unknown;

interface LoadedModule {
  mtimeMs: number;
  exports: Record<string, unknown>;
}

// esbuild rewrites import() to require() in CJS output, so keep a real dynamic import.
const nativeImport = new Function("specifier", "return import(specifier)") as (
  specifier: string,
) => Promise<Record<string, unknown>>;

const dynamicImport = async (
  specifier: string,
): Promise<Record<string, unknown>> => {
  try {
    return await nativeImport(specifier);
  } catch (e) {
    // Inside a vm context without an import callback (test runners), fall back to the bundler's import().
    if (
      (e as NodeJS.ErrnoException).code !==
      "ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING"
    ) {
      throw e;
    }
    return import(specifier);
  }
};

const packageTypeCache = new Map<string, string | undefined>();

const nearestPackageType = (dir: string): string | undefined => {
  if (packageTypeCache.has(dir)) return packageTypeCache.get(dir);
  let type: string | undefined;
  const pkg = path.join(dir, "package.json");
  if (fs.existsSync(pkg)) {
    try {
      type = JSON.parse(fs.readFileSync(pkg, "utf8")).type ?? "commonjs";
    } catch {
      type = "commonjs";
    }
  } else {
    const parent = path.dirname(dir);
    type = parent === dir ? "commonjs" : nearestPackageType(parent);
  }
  packageTypeCache.set(dir, type);
  return type;
};

export const isEsmFile = (file: string): boolean => {
  const ext = path.extname(file);
  if (ext === ".mjs" || ext === ".mts") return true;
  if (ext === ".cjs" || ext === ".cts") return false;
  return nearestPackageType(path.dirname(file)) === "module";
};

export interface FileTriggerInvokerOptions {
  timeoutMs?: number;
  hotReload?: boolean;
}

export class FileTriggerInvoker {
  private readonly modules = new Map<string, LoadedModule>();
  private readonly timeoutMs: number;
  private readonly hotReload: boolean;

  public constructor(options: FileTriggerInvokerOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? DEFAULT_FILE_TRIGGER_TIMEOUT_MS;
    this.hotReload = options.hotReload ?? true;
  }

  private async load(file: string): Promise<Record<string, unknown>> {
    let mtimeMs: number;
    try {
      mtimeMs = fs.statSync(file).mtimeMs;
    } catch {
      throw new FileTriggerError(`Cannot find trigger file ${file}`, "load");
    }
    const cached = this.modules.get(file);
    if (cached && (!this.hotReload || cached.mtimeMs === mtimeMs)) {
      return cached.exports;
    }

    let exports: Record<string, unknown>;
    try {
      if (isEsmFile(file)) {
        const url = pathToFileURL(file);
        if (cached) url.searchParams.set("v", String(mtimeMs));
        exports = await dynamicImport(url.href);
      } else {
        const req = createRequire(file);
        delete req.cache[req.resolve(file)];
        exports = req(file);
      }
    } catch (e) {
      throw new FileTriggerError(
        `Cannot load trigger file ${file}: ${(e as Error)?.message ?? e}`,
        "load",
      );
    }
    this.modules.set(file, { mtimeMs, exports });
    return exports;
  }

  public async resolveHandler(target: FileTriggerTarget): Promise<Handler> {
    const exports = await this.load(target.file);
    const nested = exports.default as Record<string, unknown> | undefined;
    const candidate =
      exports[target.exportName] ??
      (nested && typeof nested === "object"
        ? nested[target.exportName]
        : undefined);
    if (typeof candidate !== "function") {
      throw new FileTriggerError(
        `${target.file} does not export a function named "${target.exportName}"`,
        "load",
      );
    }
    return candidate as Handler;
  }

  public async invoke(
    target: FileTriggerTarget,
    functionName: string,
    event: unknown,
  ): Promise<unknown> {
    const handler = await this.resolveHandler(target);
    const started = Date.now();
    const timeoutMs = this.timeoutMs;
    const context = {
      awsRequestId: randomUUID(),
      callbackWaitsForEmptyEventLoop: true,
      functionName,
      functionVersion: "$LATEST",
      invokedFunctionArn: `arn:aws:lambda:local:local:function:${functionName}`,
      logGroupName: `/aws/lambda/${functionName}`,
      logStreamName: "cognito-local",
      memoryLimitInMB: "128",
      getRemainingTimeInMillis: () =>
        Math.max(0, timeoutMs - (Date.now() - started)),
    };

    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () =>
          reject(
            new FileTriggerError(
              `Task timed out after ${(timeoutMs / 1000).toFixed(2)} seconds`,
              "timeout",
            ),
          ),
        timeoutMs,
      );
    });

    const run = new Promise<unknown>((resolve, reject) => {
      const callback = (err?: unknown, result?: unknown) =>
        err ? reject(err) : resolve(result);
      const fail = (err: unknown) => reject(err ?? new Error("failed"));
      Object.assign(context, {
        done: callback,
        fail,
        succeed: (result: unknown) => resolve(result),
      });
      try {
        const returned = handler(event, context, callback);
        if (
          returned &&
          typeof (returned as Promise<unknown>).then === "function"
        ) {
          (returned as Promise<unknown>).then(resolve, reject);
        } else if (handler.length < 3) {
          resolve(returned);
        }
      } catch (e) {
        reject(e);
      }
    });

    try {
      return await Promise.race([run, timeout]);
    } catch (e) {
      if (e instanceof FileTriggerError) throw e;
      const message =
        e instanceof Error ? e.message : typeof e === "string" ? e : String(e);
      throw new FileTriggerError(message, "handler");
    } finally {
      clearTimeout(timer);
    }
  }
}
