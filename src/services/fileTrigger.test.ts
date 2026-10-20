import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  FileTriggerError,
  FileTriggerInvoker,
  formatFileTarget,
  isEsmFile,
  parseFileTarget,
} from "./fileTrigger";

describe("file triggers", () => {
  let dir: string;
  const write = (name: string, body: string) => {
    const file = path.join(dir, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, body);
    return file;
  };
  const target = (file: string, exportName = "handler") => ({
    file,
    exportName,
  });

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "cognito-local-triggers-"));
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  describe("parseFileTarget", () => {
    it("resolves a relative path against the base directory, defaulting the export to handler", () => {
      expect(parseFileTarget("file:./triggers/define.js", "/base")).toEqual({
        file: "/base/triggers/define.js",
        exportName: "handler",
      });
    });

    it("reads the export name after #", () => {
      expect(parseFileTarget("file:/abs/x.mjs#verify", "/base")).toEqual({
        file: "/abs/x.mjs",
        exportName: "verify",
      });
    });

    it("accepts file:// URLs", () => {
      expect(parseFileTarget("file:///abs/x.js#h").file).toBe("/abs/x.js");
    });

    it("rejects a value without the file: prefix or path", () => {
      expect(() => parseFileTarget("arn:aws:lambda:x")).toThrow(
        "is not a file: trigger target",
      );
      expect(() => parseFileTarget("file:#handler")).toThrow(
        "has no file path",
      );
    });

    it("formats a target back, omitting the default export", () => {
      expect(formatFileTarget(target("/a/b.js"))).toBe("file:/a/b.js");
      expect(formatFileTarget(target("/a/b.js", "x"))).toBe("file:/a/b.js#x");
    });
  });

  it("detects ES modules by extension and package type", () => {
    write("esm-pkg/package.json", JSON.stringify({ type: "module" }));
    expect(isEsmFile(path.join(dir, "esm-pkg/a.js"))).toBe(true);
    expect(isEsmFile(path.join(dir, "esm-pkg/a.cjs"))).toBe(false);
    expect(isEsmFile(path.join(dir, "a.mjs"))).toBe(true);
  });

  const event = () => ({ request: { n: 1 }, response: {} });

  it("runs an async CommonJS handler", async () => {
    const file = write(
      "cjs-async.js",
      "exports.handler = async (e) => { e.response.ok = e.request.n + 1; return e; };",
    );
    const result = await new FileTriggerInvoker().invoke(
      target(file),
      "PreSignUp",
      event(),
    );
    expect(result).toEqual({ request: { n: 1 }, response: { ok: 2 } });
  });

  it("runs a callback-style CommonJS handler with a named export", async () => {
    const file = write(
      "cjs-callback.js",
      "exports.verify = (e, ctx, cb) => setTimeout(() => cb(null, { ...e, response: { fn: ctx.functionName } }), 5);",
    );
    const result = await new FileTriggerInvoker().invoke(
      target(file, "verify"),
      "VerifyAuthChallengeResponse",
      event(),
    );
    expect(result).toMatchObject({
      response: { fn: "VerifyAuthChallengeResponse" },
    });
  });

  it("runs an ES module handler", async () => {
    const file = write(
      "esm.mjs",
      "export const handler = async (e) => ({ ...e, response: { esm: true } });",
    );
    const result = await new FileTriggerInvoker().invoke(
      target(file),
      "CreateAuthChallenge",
      event(),
    );
    expect(result).toMatchObject({ response: { esm: true } });
  });

  it("finds a handler on the default export", async () => {
    const file = write(
      "esm-default.mjs",
      "export default { handler: async (e) => ({ ...e, response: { d: 1 } }) };",
    );
    const result = await new FileTriggerInvoker().invoke(
      target(file),
      "CustomMessage",
      event(),
    );
    expect(result).toMatchObject({ response: { d: 1 } });
  });

  it("reports a callback error, a thrown error and a rejected promise as handler errors", async () => {
    const invoker = new FileTriggerInvoker();
    const cb = write(
      "err-cb.js",
      "exports.handler = (e, c, cb) => cb(new Error('from callback'));",
    );
    const thrown = write(
      "err-throw.js",
      "exports.handler = () => { throw new Error('thrown'); };",
    );
    const rejected = write(
      "err-reject.mjs",
      "export const handler = async () => { throw 'plain string'; };",
    );

    for (const [file, message] of [
      [cb, "from callback"],
      [thrown, "thrown"],
      [rejected, "plain string"],
    ]) {
      const error = await invoker
        .invoke(target(file), "PreSignUp", event())
        .catch((e) => e);
      expect(error).toBeInstanceOf(FileTriggerError);
      expect(error).toMatchObject({ kind: "handler", message });
    }
  });

  it("times out a handler that never finishes", async () => {
    const file = write(
      "hang.js",
      "exports.handler = () => new Promise(() => {});",
    );
    const error = await new FileTriggerInvoker({ timeoutMs: 50 })
      .invoke(target(file), "PreSignUp", event())
      .catch((e) => e);
    expect(error).toMatchObject({
      kind: "timeout",
      message: "Task timed out after 0.05 seconds",
    });
  });

  it("fails to load a missing file or export", async () => {
    const invoker = new FileTriggerInvoker();
    await expect(
      invoker.invoke(target(path.join(dir, "nope.js")), "PreSignUp", event()),
    ).rejects.toMatchObject({
      kind: "load",
      message: expect.stringContaining("Cannot find trigger file"),
    });

    const file = write("no-export.js", "exports.other = () => {};");
    await expect(
      invoker.invoke(target(file), "PreSignUp", event()),
    ).rejects.toMatchObject({
      kind: "load",
      message: expect.stringContaining(
        'does not export a function named "handler"',
      ),
    });

    const broken = write("syntax.js", "exports.handler = (;");
    await expect(
      invoker.invoke(target(broken), "PreSignUp", event()),
    ).rejects.toMatchObject({
      kind: "load",
      message: expect.stringContaining("Cannot load trigger file"),
    });
  });

  it("reloads a changed CommonJS file when hot reload is on", async () => {
    const invoker = new FileTriggerInvoker();
    const body = (v: number) =>
      `exports.handler = async (e) => ({ ...e, response: { v: ${v} } });`;
    const file = write("reload.js", body(1));
    expect(
      await invoker.invoke(target(file), "PreSignUp", event()),
    ).toMatchObject({ response: { v: 1 } });
    write("reload.js", body(2));
    const later = new Date(Date.now() + 5000);
    fs.utimesSync(file, later, later);
    expect(
      await invoker.invoke(target(file), "PreSignUp", event()),
    ).toMatchObject({ response: { v: 2 } });
  });

  // The test VM caches ES modules by path, so prove ESM reload in a real Node process.
  it("reloads a changed ES module file when hot reload is on", () => {
    const file = write(
      "reload.mjs",
      "export const handler = async (e) => ({ ...e, response: { v: 1 } });",
    );
    const script = write(
      "reload-esm.ts",
      `import fs from "node:fs";
import { FileTriggerInvoker } from ${JSON.stringify(path.resolve(__dirname, "fileTrigger.ts"))};
const invoker = new FileTriggerInvoker();
const target = { file: ${JSON.stringify(file)}, exportName: "handler" };
(async () => {
  const first = await invoker.invoke(target, "PreSignUp", { response: {} });
  fs.writeFileSync(target.file, "export const handler = async (e) => ({ ...e, response: { v: 2 } });");
  const later = new Date(Date.now() + 5000);
  fs.utimesSync(target.file, later, later);
  const second = await invoker.invoke(target, "PreSignUp", { response: {} });
  process.stdout.write(JSON.stringify([first.response.v, second.response.v]));
})();
`,
    );
    const out = execFileSync(
      path.resolve(__dirname, "../../node_modules/.bin/tsx"),
      [script],
      { encoding: "utf8" },
    );
    expect(JSON.parse(out)).toEqual([1, 2]);
  });

  it("keeps the first version when hot reload is off", async () => {
    const invoker = new FileTriggerInvoker({ hotReload: false });
    const file = write(
      "noreload.js",
      "exports.handler = async (e) => ({ ...e, response: { v: 1 } });",
    );
    await invoker.invoke(target(file), "PreSignUp", event());
    write(
      "noreload.js",
      "exports.handler = async (e) => ({ ...e, response: { v: 2 } });",
    );
    const later = new Date(Date.now() + 5000);
    fs.utimesSync(file, later, later);
    expect(
      await invoker.invoke(target(file), "PreSignUp", event()),
    ).toMatchObject({ response: { v: 1 } });
  });
});
