import { type ChildProcess, spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
} from "vitest";
import { type CliIO, runCli } from "./index";

const ROOT = path.resolve(__dirname, "../..");
const EXAMPLES = path.join(ROOT, "examples");
const BASIC = path.join(EXAMPLES, "seed.basic.json");
const OTP = path.join(EXAMPLES, "seed.custom-auth-otp.json");

const fakeIO = (opts: { isTTY?: boolean; answer?: string } = {}) => {
  const out: string[] = [];
  const err: string[] = [];
  const prompts: string[] = [];
  const io: CliIO = {
    stdout: (t) => out.push(t),
    stderr: (t) => err.push(t),
    isTTY: opts.isTTY ?? false,
    prompt: async (q) => {
      prompts.push(q);
      return opts.answer ?? "";
    },
    env: {},
  };
  return {
    io,
    stdout: () => out.join(""),
    stderr: () => err.join(""),
    json: () => JSON.parse(out.join("")),
    prompts,
  };
};

const freePort = () =>
  new Promise<number>((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as net.AddressInfo;
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });

describe("cognito-local CLI", () => {
  let data: string;

  beforeEach(() => {
    data = fs.mkdtempSync(path.join(os.tmpdir(), "cognito-local-cli-"));
  });

  afterEach(() => {
    fs.rmSync(data, { recursive: true, force: true });
  });

  describe("arguments", () => {
    it("prints usage for --help and the version for --version", async () => {
      const help = fakeIO();
      expect(await runCli(["--help"], help.io)).toBe(0);
      expect(help.stdout()).toContain("cognito-local seed <file>");
      expect(help.stdout()).toContain("cognito-emulator");
      const version = fakeIO();
      expect(await runCli(["--version"], version.io)).toBe(0);
      expect(version.stdout().trim()).not.toBe("");
    });

    it("installs both command names, one matching the package name for npx", () => {
      const pkg = JSON.parse(
        fs.readFileSync(path.join(ROOT, "package.json"), "utf8"),
      );
      expect(pkg.name).toBe("cognito-emulator");
      expect(pkg.bin).toEqual({
        "cognito-emulator": "lib/bin/cli.js",
        "cognito-local": "lib/bin/cli.js",
      });
    });

    it.each([
      [["status", "--port", "1"], '--port is not an option of "status"'],
      [["start", "extra"], 'unexpected argument "extra"'],
      [["seed"], "seed needs a file"],
      [["--bogus"], "Unknown option '--bogus'"],
      [["start", "--admin", "--no-admin"], "mutually exclusive"],
    ])("rejects %j with exit code 2", async (argv, message) => {
      const run = fakeIO();
      expect(await runCli(argv, run.io)).toBe(2);
      expect(run.stderr()).toContain(message);
    });
  });

  describe("without a running server", () => {
    it("status reports not running with exit code 3", async () => {
      const run = fakeIO();
      expect(await runCli(["status", "--data", data, "--json"], run.io)).toBe(
        3,
      );
      expect(run.json()).toMatchObject({
        running: false,
        pools: 0,
        dataDirectory: path.resolve(data),
      });
    });

    it("seed writes the data directory and is idempotent", async () => {
      const first = fakeIO();
      expect(await runCli(["seed", BASIC, "--data", data], first.io)).toBe(0);
      expect(first.stdout()).toContain("created UserPool local_Example1");
      expect(first.stdout()).toContain("9 created, 0 updated, 0 unchanged");

      const second = fakeIO();
      expect(
        await runCli(["seed", BASIC, "--data", data, "--json"], second.io),
      ).toBe(0);
      expect(second.json()).toMatchObject({
        mode: "data-directory",
        summary: { created: 0, updated: 0, unchanged: 9 },
      });

      const status = fakeIO();
      await runCli(["status", "--data", data, "--json"], status.io);
      expect(status.json().pools).toBe(1);
    });

    it("seed reports validation errors with the file path, as JSON too", async () => {
      const bad = path.join(data, "bad.json");
      fs.writeFileSync(bad, JSON.stringify({ UserPools: [{ PoolName: 1 }] }));
      const run = fakeIO();
      expect(
        await runCli(["seed", bad, "--data", data, "--json"], run.io),
      ).toBe(1);
      expect(run.json()).toEqual({
        error: `Invalid seed ${bad}:\n  - UserPools[0].PoolName: must be a string, got number`,
        issues: [
          {
            path: "UserPools[0].PoolName",
            message: "must be a string, got number",
          },
        ],
      });
    });

    it("export prints a seed, or writes one with portable trigger paths", async () => {
      await runCli(["seed", OTP, "--data", data], fakeIO().io);

      const printed = fakeIO();
      expect(await runCli(["export", "--data", data], printed.io)).toBe(0);
      expect(printed.json().UserPools[0].Id).toBe("local_OtpExample");

      const out = path.join(EXAMPLES, "exported.test-tmp.json");
      try {
        const written = fakeIO();
        expect(
          await runCli(
            ["export", "--data", data, "--out", out, "--json"],
            written.io,
          ),
        ).toBe(0);
        expect(written.json()).toMatchObject({ out, pools: 1, users: 1 });
        expect(written.json().note).toContain("Passwords are not exported");
        const seed = JSON.parse(fs.readFileSync(out, "utf8"));
        expect(seed.UserPools[0].LambdaConfig.DefineAuthChallenge).toBe(
          "file:./triggers/define-auth-challenge.js",
        );

        const fresh = path.join(data, "fresh");
        const reseed = fakeIO();
        expect(
          await runCli(["seed", out, "--data", fresh, "--json"], reseed.io),
        ).toBe(0);
        expect(reseed.json().summary.created).toBe(4);
      } finally {
        fs.rmSync(out, { force: true });
      }
    });

    it("reset needs --yes when stdin is not a terminal", async () => {
      await runCli(["seed", BASIC, "--data", data], fakeIO().io);
      const run = fakeIO({ isTTY: false });
      expect(await runCli(["reset", "--data", data], run.io)).toBe(2);
      expect(run.stderr()).toContain("Re-run with --yes");
      expect(run.prompts).toEqual([]);
      expect(fs.existsSync(path.join(data, "db"))).toBe(true);
    });

    it("reset prompts on a terminal and honours the answer", async () => {
      await runCli(["seed", BASIC, "--data", data], fakeIO().io);
      const no = fakeIO({ isTTY: true, answer: "n" });
      expect(await runCli(["reset", "--data", data], no.io)).toBe(2);
      expect(fs.existsSync(path.join(data, "db"))).toBe(true);

      const yes = fakeIO({ isTTY: true, answer: "y" });
      expect(await runCli(["reset", "--data", data], yes.io)).toBe(0);
      expect(yes.prompts[0]).toContain(path.join(data, "db"));
      expect(fs.existsSync(path.join(data, "db"))).toBe(false);
      expect(fs.existsSync(path.join(data, "config.json"))).toBe(true);
    });

    it("reset --yes --all also removes config.json", async () => {
      await runCli(["seed", BASIC, "--data", data], fakeIO().io);
      const run = fakeIO();
      expect(
        await runCli(
          ["reset", "--yes", "--all", "--data", data, "--json"],
          run.io,
        ),
      ).toBe(0);
      expect(run.json()).toMatchObject({ reset: true });
      expect(fs.readdirSync(data)).toEqual([]);
    });
  });

  describe("with a running server", () => {
    let child: ChildProcess;
    let port: number;
    let serverData: string;
    let output = "";

    beforeAll(async () => {
      serverData = fs.mkdtempSync(
        path.join(os.tmpdir(), "cognito-local-cli-server-"),
      );
      port = await freePort();
      child = spawn(
        path.join(ROOT, "node_modules/.bin/tsx"),
        [
          path.join(ROOT, "src/bin/cli.ts"),
          "start",
          "--port",
          String(port),
          "--host",
          "127.0.0.1",
          "--data",
          serverData,
          "--seed",
          BASIC,
        ],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      child.stdout?.on("data", (d) => {
        output += d;
      });
      child.stderr?.on("data", (d) => {
        output += d;
      });
      for (let i = 0; i < 100; i++) {
        const run = fakeIO();
        if ((await runCli(["status", "--data", serverData], run.io)) === 0)
          return;
        await new Promise((r) => setTimeout(r, 100));
      }
      throw new Error(`server did not start:\n${output}`);
    }, 20000);

    afterAll(async () => {
      if (child.exitCode === null) {
        child.kill("SIGTERM");
        await new Promise((r) => child.once("exit", r));
      }
      fs.rmSync(serverData, { recursive: true, force: true });
    });

    it("status finds it through the data directory and through --url", async () => {
      const run = fakeIO();
      expect(
        await runCli(["status", "--data", serverData, "--json"], run.io),
      ).toBe(0);
      expect(run.json()).toMatchObject({
        running: true,
        url: `http://127.0.0.1:${port}`,
        pid: expect.any(Number),
        pools: 1,
        adminUi: true,
        adminUrl: `http://127.0.0.1:${port}/_admin`,
      });
      expect(output).toContain("Applied seed");

      const byUrl = fakeIO();
      expect(
        await runCli(["status", "--url", `http://127.0.0.1:${port}`], byUrl.io),
      ).toBe(0);
      expect(byUrl.stdout()).toContain("1 user pool(s)");
    });

    it("seed and export go through the server's admin API", async () => {
      const seeded = fakeIO();
      expect(
        await runCli(["seed", OTP, "--data", serverData, "--json"], seeded.io),
      ).toBe(0);
      expect(seeded.json()).toMatchObject({
        mode: "server",
        url: `http://127.0.0.1:${port}`,
        summary: { created: 4 },
      });

      const exported = fakeIO();
      expect(await runCli(["export", "--data", serverData], exported.io)).toBe(
        0,
      );
      expect(
        exported.json().UserPools.map((p: { Id: string }) => p.Id),
      ).toEqual(["local_Example1", "local_OtpExample"]);
    });

    it("refuses to reset or start a second server on the same data directory", async () => {
      const reset = fakeIO();
      expect(
        await runCli(["reset", "--yes", "--data", serverData], reset.io),
      ).toBe(1);
      expect(reset.stderr()).toContain("stop it before reset");

      const start = fakeIO();
      expect(
        await runCli(["start", "--data", serverData, "--port", "0"], start.io),
      ).toBe(1);
      expect(start.stderr()).toContain("already serving");
    });

    it("removes its runtime file on SIGTERM", async () => {
      expect(fs.existsSync(path.join(serverData, "server.json"))).toBe(true);
      child.kill("SIGTERM");
      const code = await new Promise((r) => child.once("exit", r));
      expect(code).toBe(0);
      expect(fs.existsSync(path.join(serverData, "server.json"))).toBe(false);
      const run = fakeIO();
      expect(await runCli(["status", "--data", serverData], run.io)).toBe(3);
      expect(run.stdout()).toContain("not running");
    });
  });
});
