import type { Application, Request, Response } from "express";
import { CognitoError } from "../errors";
import type { Services } from "../services";
import type { Context } from "../services/context";
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
import { type AuthorizeFlow, buildErrorRedirect } from "./oauthRequest";

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
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f4f5f7; margin: 0; padding: 16px; color: #1d2330; }
  main { max-width: 560px; margin: 24px auto; background: #fff; border-radius: 8px; padding: 24px; box-shadow: 0 1px 4px rgba(0,0,0,.12); }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .note { color: #5b6475; font-size: 13px; margin: 0 0 16px; overflow-wrap: anywhere; }
  label { display: block; font-size: 13px; font-weight: 600; margin: 12px 0 4px; }
  input[type=text] { width: 100%; box-sizing: border-box; padding: 7px 8px; border: 1px solid #c4c9d4; border-radius: 4px; font-size: 14px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: 12px; color: #5b6475; font-weight: 600; padding: 8px 4px 2px; }
  td { padding: 3px 4px; }
  code { background: #eef0f4; padding: 1px 4px; border-radius: 3px; }
  .actions { display: flex; gap: 8px; margin-top: 20px; flex-wrap: wrap; }
  button { padding: 9px 16px; border-radius: 4px; border: 1px solid #1f6feb; background: #1f6feb; color: #fff; font-size: 14px; cursor: pointer; }
  button.secondary { background: #fff; color: #b42318; border-color: #b42318; }
  details { margin-top: 16px; font-size: 13px; }
  .badge { display: inline-block; font-size: 11px; background: #fff4d6; color: #7a4d00; border-radius: 10px; padding: 2px 8px; margin-left: 6px; vertical-align: middle; }
`;

const page = (title: string, body: string) => `<!DOCTYPE html>
<html>
<head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>${escapeHtml(title)}</title><style>${STYLE}</style></head>
<body><main>
${body}
</main></body>
</html>`;

const claimRow = (name: string, value: string) =>
  `    <tr><td><input type="text" name="claim_name" value="${escapeHtml(name)}" aria-label="Claim name" /></td><td><input type="text" name="claim_value" value="${escapeHtml(value)}" aria-label="Claim value" /></td></tr>\n`;

export function mockIdpPage(
  provider: IdentityProviderConfig,
  stateId: string,
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
  return page(
    `Sign in with ${provider.ProviderName}`,
    `<h1>Sign in with ${escapeHtml(provider.ProviderName)}<span class="badge">mock ${escapeHtml(provider.ProviderType)} IdP</span></h1>
<p class="note">cognito-local stands in for the identity provider: nothing leaves this machine.${
      realUrl
        ? ` Real Cognito would redirect to <code>${escapeHtml(realUrl)}</code>.`
        : ""
    }</p>
<form method="POST" action="/oauth2/idpresponse">
${hiddenInput("state", stateId)}  <label for="subject">Subject (<code>${escapeHtml(defaults.subjectClaim)}</code>)</label>
  <input type="text" id="subject" name="subject" value="${escapeHtml(defaults.subject)}" />
  <table>
    <tr><th>IdP claim</th><th>Value</th></tr>
${rows}  </table>
  <details><summary>Attribute mapping of ${escapeHtml(provider.ProviderName)}</summary>${mappingList}</details>
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

export function beginFederation(
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
): void {
  const { provider, flow } = input;
  const pending: PendingFederation = {
    clientId: input.clientId,
    userPoolId: input.userPoolId,
    providerName: provider.ProviderName,
    redirectUri: input.redirectUri,
    state: input.state || undefined,
    ...flow,
  };
  const stateId = store.create(pending);
  const base = `${req.protocol}://${req.get("host")}`;
  const query = new URLSearchParams({
    client_id: provider.ProviderDetails?.client_id ?? "",
    redirect_uri: `${base}/oauth2/idpresponse`,
    response_type: "code",
    scope: provider.ProviderDetails?.authorize_scopes ?? "",
    state: stateId,
  });
  res.redirect(
    `/mock-idp/${encodeURIComponent(provider.ProviderName)}/authorize?${query}`,
  );
}

export function attachFederationRoutes(
  app: Application,
  services: Services,
  codeStore: AuthorizationCodeStore,
  store: FederationStore,
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

  app.get(
    "/mock-idp/:providerName/authorize",
    async (req: Request, res: Response) => {
      const ctx: Context = { logger: req.log };
      const pending = store.peek(req.query.state as string | undefined);
      if (!pending || pending.providerName !== req.params.providerName) {
        return res
          .status(400)
          .type("text/html")
          .send(
            errorPage(
              "This sign-in request is unknown or has expired. Start again from your app.",
            ),
          );
      }
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
      return res
        .status(200)
        .type("text/html")
        .send(mockIdpPage(provider, req.query.state as string));
    },
  );

  const idpResponse = async (req: Request, res: Response) => {
    const ctx: Context = { logger: req.log };
    const input = (req.method === "POST" ? req.body : req.query) as Record<
      string,
      unknown
    >;
    const pending = store.consume(
      typeof input?.state === "string" ? input.state : undefined,
    );
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
    if (req.method !== "POST") {
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

      const claims = claimsFromForm(provider, input);
      const { user } = await federatedSignIn(
        ctx,
        services,
        userPool,
        appClient,
        provider,
        claims,
      );
      return await sendAuthorizationResponse(ctx, res, services, codeStore, {
        appClient,
        userPool,
        user,
        redirectUri: pending.redirectUri,
        state: pending.state,
        flow: pending,
      });
    } catch (err) {
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
