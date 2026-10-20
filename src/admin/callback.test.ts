import fs from "node:fs";
import type http from "node:http";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MockLogger } from "../__tests__/mockLogger";
import { TestContext } from "../__tests__/testContext";
import { applySeed, loadSeedFile } from "../seed";
import { createDefaultServer, type DefaultServer } from "../server/defaults";

const EXAMPLES = path.resolve(__dirname, "../../examples");

const decodeEntities = (value: string) =>
  value
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");

const formFields = (html: string) =>
  Object.fromEntries(
    [...html.matchAll(/<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"/g)].map(
      (m) => [m[1], decodeEntities(m[2])],
    ),
  );

describe("admin OAuth callback (dev tool)", () => {
  let dataDirectory: string;
  let server: DefaultServer;
  let httpServer: http.Server;
  let base: string;

  beforeEach(async () => {
    dataDirectory = fs.mkdtempSync(
      path.join(os.tmpdir(), "cognito-local-callback-"),
    );
    server = await createDefaultServer(MockLogger as never, {
      dataDirectory,
      port: 0,
      hostname: "127.0.0.1",
      adminUi: true,
    });
    httpServer = (await server.start()) as http.Server;
    const address = httpServer.address() as { port: number };
    base = `http://127.0.0.1:${address.port}`;

    const seed = loadSeedFile(path.join(EXAMPLES, "seed.basic.json"));
    seed.UserPools[0].Clients![0].CallbackURLs = [`${base}/_admin/callback`];
    await applySeed(TestContext, server.services, seed);
  });

  afterEach(async () => {
    await new Promise((resolve) => httpServer.close(resolve));
    fs.rmSync(dataDirectory, { recursive: true, force: true });
  });

  const get = (url: string) =>
    fetch(url.startsWith("http") ? url : `${base}${url}`, {
      redirect: "manual",
    });
  const post = (url: string, fields: Record<string, string>) =>
    fetch(`${base}${url}`, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields),
    });

  it("lists clients with the code flow and explains how to register the page", async () => {
    const page = await (await get("/_admin/callback")).text();
    expect(page).toContain("dev tool");
    expect(page).toContain("Not part of Amazon Cognito");
    expect(page).toContain("example / web (examplewebclient0000000001)");
    expect(page).not.toContain("examplebackendclient000001");
    expect(page).toContain(`<code>${base}/_admin/callback</code>`);
  });

  it("warns when the page is not a registered callback URL or the IdP is unknown", async () => {
    await applySeed(TestContext, server.services, {
      UserPools: [
        {
          Id: "local_Example1",
          PoolName: "example",
          Clients: [
            {
              ClientId: "examplewebclient0000000001",
              ClientName: "web",
              CallbackURLs: ["http://localhost:3000/callback"],
            },
          ],
        },
      ],
    });
    const page = await (
      await get(
        "/_admin/callback/start?client_id=examplewebclient0000000001&identity_provider=Nope",
      )
    ).text();
    expect(page).toContain("is not in this client&#39;s CallbackURLs");
    expect(page).toContain(
      "Nope is not an identity provider of local_Example1",
    );
  });

  it("runs a full code + PKCE login: start, sign in, callback, exchange, decoded tokens", async () => {
    const start = await (
      await get(
        "/_admin/callback/start?client_id=examplewebclient0000000001&pkce=1&scope=openid+email",
      )
    ).text();
    const href = decodeEntities(
      /href="(\/oauth2\/authorize\?[^"]+)"/.exec(start)?.[1] ?? "",
    );
    const authorize = new URL(href, base);
    expect(authorize.searchParams.get("redirect_uri")).toBe(
      `${base}/_admin/callback`,
    );
    expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
    expect(start).not.toContain("is not in this client");

    const loginForm = await (await get(href)).text();
    const signIn = await post("/oauth2/authorize", {
      ...formFields(loginForm),
      username: "admin@example.test",
      password: "Passw0rdAdmin",
    });
    expect(signIn.status).toBe(302);
    const location = signIn.headers.get("location") as string;
    expect(location.startsWith(`${base}/_admin/callback?code=`)).toBe(true);

    const callback = await (await get(location)).text();
    expect(callback).toContain("Authorization response");
    const fields = formFields(callback);
    expect(fields.code_verifier).toMatch(/^[\w-]{43}$/);
    expect(callback).toMatch(
      /<option value="examplewebclient0000000001" selected>/,
    );

    const exchanged = await (
      await post("/_admin/callback/exchange", {
        ...fields,
        client_id: "examplewebclient0000000001",
      })
    ).text();
    expect(exchanged).toContain("HTTP 200");
    expect(exchanged).toContain('<span class="badge ok">present</span>');
    expect(exchanged).toContain("ID token");
    expect(exchanged).toContain("&quot;token_use&quot;: &quot;id&quot;");
    expect(exchanged).toContain(
      "&quot;email&quot;: &quot;admin@example.test&quot;",
    );
  });

  it("shows an error redirect and a failed exchange", async () => {
    const page = await (
      await get(
        "/_admin/callback?error=access_denied&error_description=User+cancelled",
      )
    ).text();
    expect(page).toContain("access_denied");
    expect(page).toContain("User cancelled");
    expect(page).not.toContain("Exchange the code");

    const failed = await (
      await post("/_admin/callback/exchange", {
        code: "not-a-code",
        client_id: "examplebackendclient000001",
      })
    ).text();
    expect(failed).toContain("HTTP 400");
    expect(failed).toContain("invalid_grant");
  });
});
