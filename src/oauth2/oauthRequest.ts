import type { AppClient } from "../services/appClient";

export const COGNITO_PROVIDER = "COGNITO";
const SCOPES_REQUIRING_OPENID = ["email", "phone", "profile"];

export interface AuthorizeParams {
  client_id?: string;
  redirect_uri?: string;
  response_type?: string;
  scope?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  identity_provider?: string;
  idp_identifier?: string;
}

export interface FederatedProvider {
  ProviderName?: string;
  IdpIdentifiers?: string[];
}

export type ResponseType = "code" | "token";

export interface AuthorizeFlow {
  responseType: ResponseType;
  scopes: string[];
  codeChallenge: string | undefined;
  codeChallengeMethod: string | undefined;
}

type FederatedTarget = { kind: "federated"; providerName: string };

export type AuthorizeDecision =
  | { kind: "reject"; error: string; description: string }
  | { kind: "redirectError"; error: string; description: string }
  | (FederatedTarget & AuthorizeFlow)
  | ({ kind: "login" } & AuthorizeFlow);

export const parseScopes = (scope: string | undefined): string[] => [
  ...new Set((scope ?? "").split(/[\s+]+/).filter(Boolean)),
];

const redirectError = (
  error: string,
  description: string,
): AuthorizeDecision => ({ kind: "redirectError", error, description });

function decideScopes(
  requested: string[],
  allowed: readonly string[],
): { scopes: string[] } | AuthorizeDecision {
  if (requested.length === 0) return { scopes: [...allowed] };
  if (allowed.length > 0) {
    const notAllowed = requested.filter((s) => !allowed.includes(s));
    if (notAllowed.length > 0) {
      return redirectError(
        "invalid_scope",
        `Scope not allowed for this client: ${notAllowed.join(" ")}`,
      );
    }
  }
  const needsOpenId = requested.filter((s) =>
    SCOPES_REQUIRING_OPENID.includes(s),
  );
  if (needsOpenId.length > 0 && !requested.includes("openid")) {
    return redirectError(
      "invalid_scope",
      `${needsOpenId.join(" ")} can only be requested with openid`,
    );
  }
  return { scopes: requested };
}

function decideProvider(
  params: AuthorizeParams,
  appClient: AppClient,
  providers: readonly FederatedProvider[],
): AuthorizeDecision | FederatedTarget | null {
  const { identity_provider, idp_identifier } = params;
  const supported = appClient.SupportedIdentityProviders ?? [];

  if (identity_provider === COGNITO_PROVIDER) {
    if (supported.length > 0 && !supported.includes(COGNITO_PROVIDER)) {
      return redirectError(
        "invalid_request",
        "COGNITO is not enabled for this app client",
      );
    }
    return null;
  }
  if (!identity_provider && !idp_identifier) return null;

  const provider = identity_provider
    ? providers.find((p) => p.ProviderName === identity_provider)
    : providers.find((p) => p.IdpIdentifiers?.includes(idp_identifier ?? ""));
  const requestedName = identity_provider ?? idp_identifier;
  if (!provider?.ProviderName) {
    return redirectError(
      "invalid_request",
      `Identity provider ${requestedName} is not configured in this user pool`,
    );
  }
  if (!supported.includes(provider.ProviderName)) {
    return redirectError(
      "invalid_request",
      `Identity provider ${provider.ProviderName} is not enabled for this app client`,
    );
  }
  return { kind: "federated", providerName: provider.ProviderName };
}

export function decideAuthorize(
  params: AuthorizeParams,
  appClient: AppClient | null | undefined,
  providers: readonly FederatedProvider[] = [],
): AuthorizeDecision {
  const reject = (description: string): AuthorizeDecision => ({
    kind: "reject",
    error: "invalid_request",
    description,
  });
  if (!params.client_id) return reject("Missing client_id");
  if (!params.redirect_uri) return reject("Missing redirect_uri");
  if (!appClient) return reject("Invalid client_id");
  if (!(appClient.CallbackURLs ?? []).includes(params.redirect_uri)) {
    return reject(
      "redirect_mismatch: redirect_uri is not registered for this client",
    );
  }

  if (!params.response_type) {
    return redirectError("invalid_request", "Missing response_type");
  }
  const responseType = params.response_type.toLowerCase();
  if (responseType !== "code" && responseType !== "token") {
    return redirectError(
      "unsupported_response_type",
      "response_type must be code or token",
    );
  }
  const flow = responseType === "token" ? "implicit" : "code";
  const allowedFlows = appClient.AllowedOAuthFlows ?? [];
  if (allowedFlows.length > 0 && !allowedFlows.includes(flow)) {
    return redirectError(
      "unauthorized_client",
      `The ${flow} flow is not enabled for this client`,
    );
  }

  const { code_challenge, code_challenge_method } = params;
  if (responseType === "code" && (code_challenge || code_challenge_method)) {
    if (!code_challenge) {
      return redirectError("invalid_request", "Missing code_challenge");
    }
    if (!code_challenge_method) {
      return redirectError("invalid_request", "Missing code_challenge_method");
    }
    if (code_challenge_method !== "S256") {
      return redirectError(
        "invalid_request",
        "code_challenge_method must be S256",
      );
    }
  }

  const scopeDecision = decideScopes(
    parseScopes(params.scope),
    appClient.AllowedOAuthScopes ?? [],
  );
  if ("kind" in scopeDecision) return scopeDecision;

  const providerDecision = decideProvider(params, appClient, providers);
  if (providerDecision && providerDecision.kind !== "federated") {
    return providerDecision;
  }

  const usesPkce = responseType === "code" && Boolean(code_challenge);
  const authorizeFlow: AuthorizeFlow = {
    responseType,
    scopes: scopeDecision.scopes,
    codeChallenge: usesPkce ? code_challenge : undefined,
    codeChallengeMethod: usesPkce ? code_challenge_method : undefined,
  };
  return providerDecision
    ? { ...providerDecision, ...authorizeFlow }
    : { kind: "login", ...authorizeFlow };
}

export function buildErrorRedirect(
  redirectUri: string,
  error: string,
  description: string,
  state: string | undefined,
): string {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  url.searchParams.set("error_description", description);
  if (state) url.searchParams.set("state", state);
  return url.toString();
}

export const includesIdToken = (scopes: readonly string[]): boolean =>
  scopes.length === 0 || scopes.includes("openid");

export interface ClientCredentials {
  clientId: string | undefined;
  clientSecret: string | undefined;
  conflict: boolean;
}

export function parseClientCredentials(
  authorization: string | undefined,
  body: Record<string, string | undefined> | undefined,
): ClientCredentials {
  const bodyClientId = body?.client_id || undefined;
  const bodySecret = body?.client_secret || undefined;
  if (!authorization?.startsWith("Basic ")) {
    return {
      clientId: bodyClientId,
      clientSecret: bodySecret,
      conflict: false,
    };
  }
  const decoded = Buffer.from(authorization.slice(6), "base64").toString();
  const idx = decoded.indexOf(":");
  const headerId = idx === -1 ? decoded : decoded.slice(0, idx);
  const headerSecret = idx === -1 ? undefined : decoded.slice(idx + 1);
  return {
    clientId: headerId || bodyClientId,
    clientSecret: headerSecret ?? bodySecret,
    conflict: Boolean(bodyClientId && headerId && bodyClientId !== headerId),
  };
}

export const isClientAuthenticated = (
  appClient: Pick<AppClient, "ClientSecret">,
  presentedSecret: string | undefined,
): boolean =>
  !appClient.ClientSecret || presentedSecret === appClient.ClientSecret;

export interface ResourceServerScopes {
  Identifier?: string;
  Scopes?: readonly { ScopeName?: string }[];
}

export type ClientCredentialsDecision =
  | { kind: "grant"; scopes: string[] }
  | {
      kind: "error";
      error: "unauthorized_client" | "invalid_scope" | "invalid_grant";
    };

const customScopesOf = (
  resourceServers: readonly ResourceServerScopes[],
): Set<string> =>
  new Set(
    resourceServers.flatMap((server) =>
      (server.Scopes ?? []).map((s) => `${server.Identifier}/${s.ScopeName}`),
    ),
  );

/** client_credentials checks after client authentication: the flow, then the custom scopes. */
export function decideClientCredentials(
  appClient: Pick<
    AppClient,
    | "AllowedOAuthFlows"
    | "AllowedOAuthFlowsUserPoolClient"
    | "AllowedOAuthScopes"
  >,
  scope: string | undefined,
  resourceServers: readonly ResourceServerScopes[],
): ClientCredentialsDecision {
  if (
    appClient.AllowedOAuthFlowsUserPoolClient !== true ||
    !(appClient.AllowedOAuthFlows ?? []).includes("client_credentials")
  ) {
    return { kind: "error", error: "unauthorized_client" };
  }
  const custom = customScopesOf(resourceServers);
  const allowed = appClient.AllowedOAuthScopes ?? [];
  const requested = parseScopes(scope);
  if (requested.length === 0) {
    const scopes = allowed.filter((s) => custom.has(s));
    return scopes.length
      ? { kind: "grant", scopes }
      : { kind: "error", error: "invalid_scope" };
  }
  if (requested.some((s) => !custom.has(s))) {
    return { kind: "error", error: "invalid_scope" };
  }
  if (requested.some((s) => !allowed.includes(s))) {
    return { kind: "error", error: "invalid_grant" };
  }
  return { kind: "grant", scopes: requested };
}

/** aws_client_metadata: a URL-encoded JSON object of strings for the pre token generation trigger. */
export function parseClientMetadata(
  value: string | undefined,
): Record<string, string> | undefined | null {
  if (value === undefined || value === "") return undefined;
  try {
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return null;
    }
    return Object.fromEntries(
      Object.entries(parsed).map(([k, v]) => [
        k,
        typeof v === "string" ? v : JSON.stringify(v),
      ]),
    );
  } catch {
    return null;
  }
}
