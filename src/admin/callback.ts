import { createHash, randomBytes } from "node:crypto";
import express, { type Request, type Response } from "express";
import PublicKey from "../keys/cognitoLocal.public.json";
import { identityProvidersOf } from "../oauth2/federation";
import { COGNITO_PROVIDER } from "../oauth2/oauthRequest";
import type { Services } from "../services";
import type { AppClient } from "../services/appClient";
import type { Context } from "../services/context";
import type { UserPool } from "../services/userPoolService";
import { adminUrl, chips, html, layout, type SafeHtml } from "./html";
import { inspectToken, type TokenInspection } from "./tokens";

const PENDING_TTL_MS = 10 * 60 * 1000;

interface PendingLogin {
  clientId: string;
  codeVerifier?: string;
  expiresAt: number;
}

interface ClientChoice {
  pool: UserPool;
  client: AppClient;
}

export interface TokenExchangeResult {
  status: number;
  body: Record<string, unknown>;
  idToken?: TokenInspection;
  accessToken?: TokenInspection;
  refreshToken: boolean;
}

const str = (value: unknown): string =>
  typeof value === "string" ? value.trim() : "";

const ctxOf = (req: Request): Context => ({ logger: req.log });

export const callbackUrlOf = (req: Request) =>
  `${req.protocol}://${req.get("host")}${adminUrl("callback")}`;

const base64url = (buffer: Buffer) => buffer.toString("base64url");

const DEV_TOOL_NOTE = html`<p class="sub"><span class="badge warn">dev tool</span> Not part of Amazon Cognito: a cognito-local page that plays the app's redirect URI so you can test the hosted login and federation without writing a client.</p>`;

const clientLabel = ({ pool, client }: ClientChoice) =>
  `${pool.Name ?? pool.Id} / ${client.ClientName} (${client.ClientId})`;

const clientSelect = (
  choices: readonly ClientChoice[],
  selected: string | undefined,
) =>
  html`<label>App client<select name="client_id" required>${choices.map(
    (c) =>
      html`<option value="${c.client.ClientId}" ${c.client.ClientId === selected ? "selected" : ""}>${clientLabel(c)}${c.client.ClientSecret ? " · secret" : ""}</option>`,
  )}</select></label>`;

const tokenPanels = (title: string, inspection: TokenInspection | undefined) =>
  inspection
    ? html`<div class="panel"><h2>${title}</h2>${
        inspection.error
          ? html`<p class="check-fail">${inspection.error}</p>`
          : html`<table><tbody>${inspection.checks.map(
              (c) =>
                html`<tr><td class="${c.ok ? "check-ok" : "check-fail"}">${c.ok ? "pass" : "fail"}</td><td>${c.name}</td><td class="muted">${c.detail}</td></tr>`,
            )}</tbody></table>
<div class="grid" style="margin-top:12px"><pre>${JSON.stringify(inspection.header, null, 2)}</pre><pre>${JSON.stringify(inspection.payload, null, 2)}</pre></div>`
      }</div>`
    : "";

export const startPage = (opts: {
  choices: readonly ClientChoice[];
  callbackUrl: string;
}) => html`
<h1>OAuth callback</h1>
${DEV_TOOL_NOTE}
<div class="panel">
  <h2>Start a login</h2>
  ${
    opts.choices.length
      ? html`<form method="GET" action="${adminUrl("callback", "start")}">
    <div class="row">
      ${clientSelect(opts.choices, undefined)}
      <label>Identity provider<input name="identity_provider" placeholder="COGNITO, or a provider name of the pool" /></label>
    </div>
    <div class="row" style="margin-top:8px">
      <label>Scopes<input name="scope" placeholder="the client's AllowedOAuthScopes" /></label>
      <label class="check"><input type="checkbox" name="pkce" value="1" checked /> PKCE (S256)</label>
      <button class="primary" type="submit">Build authorize URL</button>
    </div>
  </form>`
      : html`<p class="empty">No app client has the OAuth code flow enabled. Set <code>AllowedOAuthFlowsUserPoolClient: true</code> and <code>AllowedOAuthFlows: ["code"]</code> on a client.</p>`
  }
</div>
<div class="panel">
  <h2>Register this page as a redirect URI</h2>
  <p>Add <code>${opts.callbackUrl}</code> to the client's <code>CallbackURLs</code> (seed file, <code>UpdateUserPoolClient</code> or the AWS CLI), then sign in through <code>/oauth2/authorize</code>. The authorization code comes back here and you can exchange it at <code>/oauth2/token</code>.</p>
</div>`;

export const authorizeUrlPage = (opts: {
  url: string;
  choice: ClientChoice;
  callbackUrl: string;
  warnings: readonly string[];
}) => html`
<div class="crumbs"><a href="${adminUrl("callback")}">OAuth callback</a></div>
<h1>Authorize URL</h1>
${DEV_TOOL_NOTE}
<div class="panel">
  <dl>
    <dt>Client</dt><dd>${clientLabel(opts.choice)}</dd>
    <dt>Redirect URI</dt><dd><code>${opts.callbackUrl}</code></dd>
    <dt>URL</dt><dd><code>${opts.url}</code></dd>
  </dl>
  ${opts.warnings.map((w) => html`<div class="flash error" role="alert" style="margin-top:12px">${w}</div>`)}
  <p style="margin-top:12px"><a class="badge" href="${opts.url}">Continue to /oauth2/authorize</a></p>
</div>`;

export const callbackPage = (opts: {
  query: Record<string, string>;
  choices: readonly ClientChoice[];
  selectedClientId?: string;
  codeVerifier?: string;
  callbackUrl: string;
  result?: TokenExchangeResult;
}) => {
  const { query } = opts;
  return html`
<div class="crumbs"><a href="${adminUrl("callback")}">OAuth callback</a></div>
<h1>Authorization response</h1>
${DEV_TOOL_NOTE}
<div class="panel">
  <dl>
    ${query.code ? html`<dt>code</dt><dd><code>${query.code}</code></dd>` : ""}
    ${query.state ? html`<dt>state</dt><dd><code>${query.state}</code></dd>` : ""}
    ${query.error ? html`<dt>error</dt><dd class="check-fail"><code>${query.error}</code></dd>` : ""}
    ${query.error_description ? html`<dt>error_description</dt><dd>${query.error_description}</dd>` : ""}
  </dl>
</div>
${
  query.code && !opts.result
    ? html`<form method="POST" action="${adminUrl("callback", "exchange")}" class="panel">
  <h2>Exchange the code at /oauth2/token</h2>
  <input type="hidden" name="code" value="${query.code}" />
  <input type="hidden" name="state" value="${query.state ?? ""}" />
  <div class="row">
    ${clientSelect(opts.choices, opts.selectedClientId)}
    <label>Redirect URI<input name="redirect_uri" value="${opts.callbackUrl}" /></label>
    <label>PKCE code_verifier<input name="code_verifier" value="${opts.codeVerifier ?? ""}" placeholder="only if the login used PKCE" /></label>
    <button class="primary" type="submit">Exchange code</button>
  </div>
  <p class="muted">A client secret is read from the emulator's store and sent with HTTP Basic auth.</p>
</form>`
    : ""
}
${
  opts.result
    ? html`<div class="panel">
  <h2>Token response <span class="badge ${opts.result.status === 200 ? "ok" : "err"}">HTTP ${opts.result.status}</span></h2>
  <dl>
    <dt>Refresh token</dt><dd>${opts.result.refreshToken ? html`<span class="badge ok">present</span>` : html`<span class="badge muted">absent</span>`}</dd>
    <dt>Fields</dt><dd>${chips(Object.keys(opts.result.body))}</dd>
  </dl>
  <pre style="margin-top:12px">${JSON.stringify(opts.result.body, null, 2)}</pre>
</div>
${tokenPanels("ID token", opts.result.idToken)}
${tokenPanels("Access token", opts.result.accessToken)}`
    : ""
}
<p><a href="${adminUrl("callback")}">Start another login</a></p>`;
};

export const createCallbackRouter = (services: Services): express.Router => {
  const router = express.Router();
  const pending = new Map<string, PendingLogin>();

  const remember = (state: string, login: Omit<PendingLogin, "expiresAt">) => {
    const now = Date.now();
    for (const [key, value] of pending) {
      if (value.expiresAt < now) pending.delete(key);
    }
    pending.set(state, { ...login, expiresAt: now + PENDING_TTL_MS });
  };

  const oauthClients = async (ctx: Context): Promise<ClientChoice[]> => {
    const out: ClientChoice[] = [];
    for (const pool of await services.cognito.listUserPools(ctx)) {
      for (const client of await services.cognito.listAppClients(
        ctx,
        pool.Id,
      )) {
        out.push({ pool, client });
      }
    }
    return out;
  };

  const send = (res: Response, title: string, body: SafeHtml, status = 200) =>
    res
      .status(status)
      .type("html")
      .set("Cache-Control", "no-store")
      .send(layout({ title, active: "callback", body }));

  const inspect = (token: unknown, choice: ClientChoice | undefined) =>
    typeof token === "string"
      ? inspectToken(token, {
          jwks: [PublicKey.jwk],
          expectedIssuer: choice
            ? `${services.config.TokenConfig?.IssuerDomain}/${choice.pool.Id}`
            : undefined,
          clientIds: choice ? [choice.client.ClientId] : undefined,
          now: services.clock.get(),
        })
      : undefined;

  router.get("/", async (req, res) => {
    const ctx = ctxOf(req);
    const query = Object.fromEntries(
      ["code", "state", "error", "error_description"]
        .map((k) => [k, str(req.query[k])])
        .filter(([, v]) => v),
    );
    const all = await oauthClients(ctx);
    if (!query.code && !query.error) {
      send(
        res,
        "OAuth callback",
        startPage({
          choices: all.filter(
            (c) =>
              c.client.AllowedOAuthFlowsUserPoolClient &&
              c.client.AllowedOAuthFlows?.includes("code"),
          ),
          callbackUrl: callbackUrlOf(req),
        }),
      );
      return;
    }
    const login = query.state ? pending.get(query.state) : undefined;
    send(
      res,
      "Authorization response",
      callbackPage({
        query,
        choices: all,
        selectedClientId: login?.clientId,
        codeVerifier: login?.codeVerifier,
        callbackUrl: callbackUrlOf(req),
      }),
    );
  });

  router.get("/start", async (req, res) => {
    const ctx = ctxOf(req);
    const clientId = str(req.query.client_id);
    const choice = (await oauthClients(ctx)).find(
      (c) => c.client.ClientId === clientId,
    );
    if (!choice) {
      send(
        res,
        "Authorize URL",
        html`<h1>Authorize URL</h1><div class="flash error" role="alert">Unknown app client ${clientId}</div>`,
        404,
      );
      return;
    }
    const callbackUrl = callbackUrlOf(req);
    const state = base64url(randomBytes(12));
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: callbackUrl,
      response_type: "code",
      scope:
        str(req.query.scope) ||
        (choice.client.AllowedOAuthScopes ?? ["openid"]).join(" "),
      state,
    });
    const provider = str(req.query.identity_provider);
    if (provider) params.set("identity_provider", provider);
    let codeVerifier: string | undefined;
    if (req.query.pkce === "1") {
      codeVerifier = base64url(randomBytes(32));
      params.set(
        "code_challenge",
        base64url(createHash("sha256").update(codeVerifier).digest()),
      );
      params.set("code_challenge_method", "S256");
    }
    remember(state, { clientId, codeVerifier });

    const warnings: string[] = [];
    if (!choice.client.CallbackURLs?.includes(callbackUrl)) {
      warnings.push(
        `${callbackUrl} is not in this client's CallbackURLs, so /oauth2/authorize will refuse the redirect. Add it to CallbackURLs first.`,
      );
    }
    const providers = [
      COGNITO_PROVIDER,
      ...identityProvidersOf(choice.pool).map((p) => p.ProviderName),
    ];
    if (provider && !providers.includes(provider)) {
      warnings.push(
        `${provider} is not an identity provider of ${choice.pool.Id} (known: ${providers.join(", ")}).`,
      );
    }

    send(
      res,
      "Authorize URL",
      authorizeUrlPage({
        url: `/oauth2/authorize?${params}`,
        choice,
        callbackUrl,
        warnings,
      }),
    );
  });

  router.post("/exchange", async (req, res) => {
    const ctx = ctxOf(req);
    const body = req.body as Record<string, unknown>;
    const clientId = str(body.client_id);
    const code = str(body.code);
    const state = str(body.state);
    const all = await oauthClients(ctx);
    const choice = all.find((c) => c.client.ClientId === clientId);
    const form = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      code,
      redirect_uri: str(body.redirect_uri) || callbackUrlOf(req),
    });
    const verifier = str(body.code_verifier);
    if (verifier) form.set("code_verifier", verifier);
    const headers: Record<string, string> = {
      "content-type": "application/x-www-form-urlencoded",
    };
    if (choice?.client.ClientSecret) {
      headers.authorization = `Basic ${Buffer.from(`${clientId}:${choice.client.ClientSecret}`).toString("base64")}`;
    }

    let result: TokenExchangeResult;
    try {
      const response = await fetch(
        `${req.protocol}://${req.get("host")}/oauth2/token`,
        { method: "POST", headers, body: form },
      );
      const json = (await response.json().catch(() => ({}))) as Record<
        string,
        unknown
      >;
      result = {
        status: response.status,
        body: json,
        idToken: inspect(json.id_token, choice),
        accessToken: inspect(json.access_token, choice),
        refreshToken: typeof json.refresh_token === "string",
      };
    } catch (e) {
      result = {
        status: 0,
        body: { error: (e as Error).message },
        refreshToken: false,
      };
    }
    if (state) pending.delete(state);

    send(
      res,
      "Token response",
      callbackPage({
        query: { code, ...(state ? { state } : {}) },
        choices: all,
        selectedClientId: clientId,
        callbackUrl: callbackUrlOf(req),
        result,
      }),
    );
  });

  return router;
};
