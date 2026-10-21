import type { Application, Request, Response } from "express";
import { CognitoError } from "../errors";
import type { FederationConfig } from "../server/config";
import {
  emulatorBanner,
  emulatorBannerStyle,
  PRODUCT_NAME,
} from "../server/emulatorBanner";
import type { Services } from "../services";
import { type Context, requestContext } from "../services/context";
import type { AuthorizationCodeStore } from "./authorizationCodeStore";
import { sendAuthorizationResponse } from "./authorizationResponse";
import { federatedSignIn } from "./federatedSignIn";
import {
  claimsFromForm,
  type IdentityProviderConfig,
  identityProvidersOf,
  mockIdpDefaults,
} from "./federation";
import type { FederationStore, PendingFederation } from "./federationStore";
import { escapeHtml, hiddenInput } from "./html";
import {
  chooserAccounts,
  isMockAccountEmail,
  type MockAccount,
  mockAccountClaims,
  mockIdpView,
  rememberMockAccount,
  resolveMockAccount,
} from "./mockIdpAccounts";
import { mockIdpSignInPage } from "./mockIdpSignInPage";
import { type AuthorizeFlow, buildErrorRedirect } from "./oauthRequest";
import {
  federationModeFor,
  RealIdp,
  RealIdpError,
  supportsRealFederation,
} from "./realIdp";

const REAL_AUTHORIZE_URLS: Record<string, string> = {
  Google: "https://accounts.google.com/o/oauth2/v2/auth",
  Facebook: "https://www.facebook.com/dialog/oauth",
  LoginWithAmazon: "https://www.amazon.com/ap/oa",
  SignInWithApple: "https://appleid.apple.com/auth/authorize",
};

function realAuthorizeUrl(provider: IdentityProviderConfig): string {
  const details = provider.ProviderDetails ?? {};
  if (provider.ProviderType === "OIDC") {
    return (
      details.authorize_url ??
      (details.oidc_issuer ? `${details.oidc_issuer}/authorize` : "")
    );
  }
  if (provider.ProviderType === "SAML") {
    return details.MetadataURL ?? "SAML IdP from MetadataFile";
  }
  return REAL_AUTHORIZE_URLS[provider.ProviderType] ?? "";
}

const STYLE = `
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f4f5f7; margin: 0; color: #1d2330; }
  main { max-width: 600px; margin: 24px auto; background: #fff; border-radius: 8px; padding: 24px; box-shadow: 0 1px 4px rgba(0,0,0,.12); }
  @media (max-width: 640px) { main { margin: 0; border-radius: 0; box-shadow: none; } }
  h1 { font-size: 20px; margin: 0 0 12px; }
  .note { color: #5b6475; font-size: 13px; margin: 0 0 16px; overflow-wrap: anywhere; }
  .explain { background: #eef3fd; border: 1px solid #c9d8f5; border-radius: 6px; padding: 10px 14px; font-size: 14px; margin: 0 0 16px; }
  .explain p { margin: 6px 0; }
  .target { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; font-size: 13px; margin: 0 0 12px; }
  .target dt { color: #5b6475; }
  .target dd { margin: 0; overflow-wrap: anywhere; }
  label { display: block; font-size: 13px; font-weight: 600; margin: 12px 0 4px; }
  input[type=text] { width: 100%; box-sizing: border-box; padding: 7px 8px; border: 1px solid #c4c9d4; border-radius: 4px; font-size: 14px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: start; font-size: 12px; color: #5b6475; font-weight: 600; padding: 8px 4px 2px; }
  td { padding: 3px 4px; }
  code { background: #eef0f4; padding: 1px 4px; border-radius: 3px; }
  .actions { display: flex; gap: 8px; margin-top: 20px; flex-wrap: wrap; }
  button { padding: 9px 16px; border-radius: 4px; border: 1px solid #1f6feb; background: #1f6feb; color: #fff; font-size: 14px; cursor: pointer; }
  button.secondary { background: #fff; color: #b42318; border-color: #b42318; }
  details { margin-top: 16px; font-size: 13px; }
  .back { margin: 0 0 12px; font-size: 13px; }
  .back a { color: #1f6feb; }
  .badge { display: inline-block; font-size: 11px; background: #fff4d6; color: #7a4d00; border-radius: 10px; padding: 2px 8px; margin-inline-start: 6px; vertical-align: middle; }
`;

const page = (title: string, body: string) => `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>${escapeHtml(title)} · ${PRODUCT_NAME}</title>${emulatorBannerStyle()}<style>${STYLE}</style></head>
<body>
${emulatorBanner()}
<main>
${body}
</main></body>
</html>`;

const claimRow = (name: string, value: string) =>
  `    <tr><td><input type="text" name="claim_name" value="${escapeHtml(name)}" aria-label="Claim name" /></td><td><input type="text" name="claim_value" value="${escapeHtml(value)}" aria-label="Claim value" /></td></tr>\n`;

/** Where a mock IdP sign-in returns to, shown on the page. */
export interface MockIdpTarget {
  clientId: string;
  clientName?: string;
  userPoolId: string;
  redirectUri: string;
}

const targetList = (target: MockIdpTarget | undefined) =>
  target
    ? `<dl class="target">
  <dt>App client</dt><dd>${target.clientName ? `${escapeHtml(target.clientName)} ` : ""}<code>${escapeHtml(target.clientId)}</code> in user pool <code>${escapeHtml(target.userPoolId)}</code></dd>
  <dt>Returns to</dt><dd><code>${escapeHtml(target.redirectUri)}</code></dd>
</dl>
`
    : "";

export function mockIdpPage(
  provider: IdentityProviderConfig,
  stateId: string,
  target?: MockIdpTarget,
  signInHref?: string,
): string {
  const defaults = mockIdpDefaults(provider);
  const rows = [
    ...defaults.fields.map((f) => claimRow(f.claim, f.value)),
    ...defaults.extras.map(([name, value]) => claimRow(name, value)),
    claimRow("", ""),
    claimRow("", ""),
  ].join("");
  const mapping = Object.entries(provider.AttributeMapping ?? {});
  const mappingList = mapping.length
    ? `<ul>${mapping
        .map(
          ([poolAttribute, idpAttribute]) =>
            `<li><code>${escapeHtml(poolAttribute)}</code> &larr; <code>${escapeHtml(idpAttribute)}</code></li>`,
        )
        .join("")}</ul>`
    : "<p>No AttributeMapping: only <code>sub</code> and <code>identities</code> are set on the user.</p>";
  const realUrl = realAuthorizeUrl(provider);
  const name = escapeHtml(provider.ProviderName);
  return page(
    `Sign in with ${provider.ProviderName} (mock)`,
    `${signInHref ? `<p class="back"><a href="${escapeHtml(signInHref)}">Back to the ${name} sign-in page</a></p>\n` : ""}<h1>Sign in with ${name}<span class="badge">mock ${escapeHtml(provider.ProviderType)} IdP</span></h1>
<div class="explain">
  <p>This page plays the role of ${name}'s login page, so no real ${name} account is needed and nothing leaves this machine.</p>
  <p>Pick who signs in: Subject is the user's id at ${name}, the rows are the claims ${name} would return. Press <strong>Sign in</strong> to continue to the app as that user; the same Subject signs in as the same user next time.</p>
  <p><strong>Simulate IdP error</strong> returns to the app as if the user cancelled at ${name}, with <code>error=access_denied</code> and the description below.</p>
</div>
${targetList(target)}${
  realUrl
    ? `<p class="note">With real Amazon Cognito the browser would go to <code>${escapeHtml(realUrl)}</code> instead.</p>\n`
    : ""
}<form method="POST" action="/oauth2/idpresponse">
${hiddenInput("state", stateId)}  <label for="subject">Subject (<code>${escapeHtml(defaults.subjectClaim)}</code>)</label>
  <input type="text" id="subject" name="subject" value="${escapeHtml(defaults.subject)}" />
  <table>
    <tr><th>IdP claim</th><th>Value</th></tr>
${rows}  </table>
  <details><summary>Attribute mapping of ${name}</summary>${mappingList}</details>
  <label for="error_description">Error description (used by "Simulate IdP error")</label>
  <input type="text" id="error_description" name="error_description" value="User cancelled the sign-in" />
  <div class="actions">
    <button type="submit" name="action" value="signin">Sign in</button>
    <button type="submit" class="secondary" name="error" value="access_denied">Simulate IdP error (access_denied)</button>
  </div>
</form>`,
  );
}

const errorPage = (message: string) =>
  page(
    "Sign-in error",
    `<h1>Sign-in error</h1><p class="note">${escapeHtml(message)}</p>`,
  );

export async function beginFederation(
  req: Request,
  res: Response,
  store: FederationStore,
  input: {
    clientId: string;
    userPoolId: string;
    redirectUri: string;
    state: string | undefined;
    provider: IdentityProviderConfig;
    flow: AuthorizeFlow;
  },
  real?: { idp: RealIdp; config: FederationConfig | undefined },
): Promise<void> {
  const { provider, flow } = input;
  const pending: PendingFederation = {
    clientId: input.clientId,
    userPoolId: input.userPoolId,
    providerName: provider.ProviderName,
    redirectUri: input.redirectUri,
    state: input.state || undefined,
    ...flow,
  };
  const base = `${req.protocol}://${req.get("host")}`;
  const idpRedirectUri = `${base}/oauth2/idpresponse`;

  if (real && federationModeFor(real.config, provider) === "real") {
    if (supportsRealFederation(provider)) {
      try {
        const signIn = await real.idp.begin(provider, idpRedirectUri);
        const stateId = store.create({ ...pending, real: signIn });
        return res.redirect(real.idp.authorizeUrl(provider, signIn, stateId));
      } catch (err) {
        const error = err instanceof RealIdpError ? err : undefined;
        return res.redirect(
          buildErrorRedirect(
            pending.redirectUri,
            error?.error ?? "server_error",
            error?.description ?? "Internal server error",
            pending.state,
          ),
        );
      }
    }
    req.log?.warn?.(
      `${provider.ProviderName} is a ${provider.ProviderType} provider, which has no real mode: using the mock IdP`,
    );
  }

  const stateId = store.create(pending);
  const query = new URLSearchParams({
    client_id: provider.ProviderDetails?.client_id ?? "",
    redirect_uri: idpRedirectUri,
    response_type: "code",
    scope: provider.ProviderDetails?.authorize_scopes ?? "",
    state: stateId,
  });
  res.redirect(
    `/mock-idp/${encodeURIComponent(provider.ProviderName)}/authorize?${query}`,
  );
}

export type OnFederatedSignIn = (
  req: Request,
  res: Response,
  userPoolId: string,
  username: string,
) => void;

export function attachFederationRoutes(
  app: Application,
  services: Services,
  codeStore: AuthorizationCodeStore,
  store: FederationStore,
  onSignIn?: OnFederatedSignIn,
  realIdp: RealIdp = new RealIdp(services.clock),
): void {
  const loadProvider = async (
    ctx: Context,
    pending: PendingFederation,
  ): Promise<IdentityProviderConfig | undefined> => {
    const userPool = await services.cognito.getUserPool(
      ctx,
      pending.userPoolId,
    );
    return identityProvidersOf(userPool.options).find(
      (p) => p.ProviderName === pending.providerName,
    );
  };

  const renderMockIdp = async (
    req: Request,
    res: Response,
    ctx: Context,
    pending: PendingFederation,
    query: Record<string, unknown>,
    problem?: { error: string; email: string; name: string },
  ) => {
    const stateId = String(query.state);
    const viewHref = (dev: "0" | "1") => {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(query)) {
        if (key !== "dev" && typeof value === "string") params.set(key, value);
      }
      params.set("dev", dev);
      return `/mock-idp/${encodeURIComponent(pending.providerName)}/authorize?${params}`;
    };
    const provider = await loadProvider(ctx, pending).catch(() => undefined);
    if (!provider) {
      return res
        .status(400)
        .type("text/html")
        .send(
          errorPage(
            `Identity provider ${pending.providerName} no longer exists.`,
          ),
        );
    }
    const appClient = await services.cognito
      .getAppClient(ctx, pending.clientId)
      .catch(() => null);
    const federation = services.config?.FederationConfig;
    const view = problem
      ? "signin"
      : mockIdpView(federation, provider, query.dev);
    if (view === "developer") {
      return res
        .status(200)
        .type("text/html")
        .send(
          mockIdpPage(
            provider,
            stateId,
            {
              clientId: pending.clientId,
              clientName: appClient?.ClientName,
              userPoolId: pending.userPoolId,
              redirectUri: pending.redirectUri,
            },
            viewHref("0"),
          ),
        );
    }
    return res
      .status(problem ? 400 : 200)
      .type("text/html")
      .send(
        mockIdpSignInPage({
          provider,
          stateId,
          accounts: chooserAccounts(req, federation, provider),
          appName: appClient?.ClientName || pending.clientId,
          redirectUri: pending.redirectUri,
          realUrl: realAuthorizeUrl(provider),
          developerHref: viewHref("1"),
          ...problem,
        }),
      );
  };

  app.get(
    "/mock-idp/:providerName/authorize",
    async (req: Request, res: Response) => {
      const ctx = requestContext(req, services.config?.TokenConfig);
      const stateId = req.query.state as string | undefined;
      const pending = store.peek(stateId);
      if (
        !stateId ||
        !pending ||
        pending.real ||
        pending.providerName !== req.params.providerName
      ) {
        return res
          .status(400)
          .type("text/html")
          .send(
            errorPage(
              "This sign-in request is unknown or has expired. Start again from your app.",
            ),
          );
      }
      return renderMockIdp(req, res, ctx, pending, req.query);
    },
  );

  const idpResponse = async (req: Request, res: Response) => {
    const ctx = requestContext(req, services.config?.TokenConfig);
    const input = (req.method === "POST" ? req.body : req.query) as Record<
      string,
      unknown
    >;
    const stateId = typeof input?.state === "string" ? input.state : undefined;
    const accountEmail =
      req.method === "POST" && typeof input?.account_email === "string"
        ? input.account_email.trim()
        : undefined;
    const accountName =
      typeof input?.account_name === "string" ? input.account_name : "";
    if (
      accountEmail !== undefined &&
      !input.error &&
      !isMockAccountEmail(accountEmail)
    ) {
      const waiting = store.peek(stateId);
      if (stateId && waiting && !waiting.real) {
        return renderMockIdp(
          req,
          res,
          ctx,
          waiting,
          { state: stateId },
          {
            error: accountEmail
              ? "Enter a valid email address."
              : "Enter an email address.",
            email: accountEmail,
            name: accountName,
          },
        );
      }
    }
    const pending = store.consume(stateId);
    if (!pending) {
      return res
        .status(400)
        .type("text/html")
        .send(errorPage("Invalid or expired state."));
    }
    const redirectError = (error: string, description: string) =>
      res.redirect(
        buildErrorRedirect(
          pending.redirectUri,
          error,
          description,
          pending.state,
        ),
      );

    if (typeof input.error === "string" && input.error) {
      const description =
        typeof input.error_description === "string" && input.error_description
          ? input.error_description
          : `${pending.providerName} returned ${input.error}`;
      return redirectError(input.error, description);
    }
    const code = typeof input.code === "string" ? input.code : "";
    if (pending.real && !code) {
      return redirectError(
        "invalid_request",
        `${pending.providerName} did not return an authorization code`,
      );
    }
    if (!pending.real && req.method !== "POST") {
      return redirectError(
        "invalid_request",
        "The identity provider response is missing",
      );
    }

    try {
      const appClient = await services.cognito.getAppClient(
        ctx,
        pending.clientId,
      );
      const userPool = await services.cognito.getUserPool(
        ctx,
        pending.userPoolId,
      );
      const provider = identityProvidersOf(userPool.options).find(
        (p) => p.ProviderName === pending.providerName,
      );
      if (!appClient || !provider) {
        return redirectError(
          "invalid_request",
          `Identity provider ${pending.providerName} is not configured in this user pool`,
        );
      }
      if (
        !(appClient.SupportedIdentityProviders ?? []).includes(
          provider.ProviderName,
        )
      ) {
        return redirectError(
          "invalid_request",
          `Identity provider ${provider.ProviderName} is not enabled for this app client`,
        );
      }

      let account: MockAccount | undefined;
      if (!pending.real && accountEmail !== undefined) {
        account = resolveMockAccount(
          req,
          services.config?.FederationConfig,
          provider,
          accountEmail,
          accountName,
        );
      }
      const claims = pending.real
        ? await realIdp.complete(
            provider,
            pending.real,
            code,
            typeof input.user === "string" ? input.user : undefined,
          )
        : account
          ? mockAccountClaims(provider, account)
          : claimsFromForm(provider, input);
      const { user } = await federatedSignIn(
        ctx,
        services,
        userPool,
        appClient,
        provider,
        claims,
      );
      onSignIn?.(req, res, userPool.options.Id, user.Username);
      if (account) rememberMockAccount(req, res, provider, account);
      return await sendAuthorizationResponse(ctx, res, services, codeStore, {
        appClient,
        userPool,
        user,
        redirectUri: pending.redirectUri,
        state: pending.state,
        flow: pending,
      });
    } catch (err) {
      if (err instanceof RealIdpError) {
        ctx.logger.warn(err.description);
        return redirectError(err.error, err.description);
      }
      if (err instanceof CognitoError) {
        return redirectError("invalid_request", err.message);
      }
      ctx.logger.error(err, "federated sign-in failed");
      return redirectError("server_error", "Internal server error");
    }
  };

  app.get("/oauth2/idpresponse", idpResponse);
  app.post("/oauth2/idpresponse", idpResponse);
}
