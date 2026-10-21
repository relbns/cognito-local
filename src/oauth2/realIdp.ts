import { createHash, createPublicKey, randomBytes } from "node:crypto";
import jwt, { type Algorithm, type JwtPayload } from "jsonwebtoken";
import type { FederationConfig, FederationMode } from "../server/config";
import type { Clock } from "../services/clock";
import {
  type Claims,
  type IdentityProviderConfig,
  subjectClaimName,
} from "./federation";

const HTTP_TIMEOUT_MS = 10_000;
const METADATA_TTL_MS = 10 * 60 * 1000;
const ID_TOKEN_ALGORITHMS: Algorithm[] = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "HS256",
  "HS384",
  "HS512",
];

export type RealProtocol = "oidc" | "oauth2";

export interface RealEndpoints {
  protocol: RealProtocol;
  authorizeUrl: string;
  tokenUrl: string;
  tokenRequestMethod: "GET" | "POST";
  attributesUrl: string | undefined;
  attributesRequestMethod: "GET" | "POST";
  addAttributes: boolean;
  jwksUri: string | undefined;
  issuer: string | undefined;
  pkce: boolean;
}

export interface RealSignIn {
  endpoints: RealEndpoints;
  redirectUri: string;
  nonce: string | undefined;
  codeVerifier: string | undefined;
}

export class RealIdpError extends Error {
  constructor(
    readonly error: string,
    readonly description: string,
  ) {
    super(description);
  }
}

const invalid = (description: string) =>
  new RealIdpError("invalid_request", description);

export function federationModeFor(
  config: FederationConfig | undefined,
  provider: IdentityProviderConfig,
): FederationMode {
  return (
    config?.Providers?.[provider.ProviderName]?.Mode ?? config?.Mode ?? "mock"
  );
}

export const supportsRealFederation = (provider: IdentityProviderConfig) =>
  provider.ProviderType !== "SAML";

interface SocialDefaults {
  protocol: RealProtocol;
  issuer?: string;
  authorizeUrl?: string;
  tokenUrl?: string;
  tokenRequestMethod?: "GET" | "POST";
  attributesUrl?: string;
  addAttributes?: boolean;
}

function socialDefaults(provider: IdentityProviderConfig): SocialDefaults {
  switch (provider.ProviderType) {
    case "Google":
      return { protocol: "oidc", issuer: "https://accounts.google.com" };
    case "SignInWithApple":
      return { protocol: "oidc", issuer: "https://appleid.apple.com" };
    case "Facebook": {
      const version = provider.ProviderDetails?.api_version || "v17.0";
      return {
        protocol: "oauth2",
        authorizeUrl: `https://www.facebook.com/${version}/dialog/oauth`,
        tokenUrl: `https://graph.facebook.com/${version}/oauth/access_token`,
        tokenRequestMethod: "GET",
        attributesUrl: `https://graph.facebook.com/${version}/me?fields=`,
        addAttributes: true,
      };
    }
    case "LoginWithAmazon":
      return {
        protocol: "oauth2",
        authorizeUrl: "https://www.amazon.com/ap/oa",
        tokenUrl: "https://api.amazon.com/auth/o2/token",
        tokenRequestMethod: "POST",
        attributesUrl: "https://api.amazon.com/user/profile",
      };
    default:
      return { protocol: "oidc" };
  }
}

const httpMethod = (
  value: string | undefined,
  fallback: "GET" | "POST",
): "GET" | "POST" => {
  const upper = value?.toUpperCase();
  return upper === "GET" || upper === "POST" ? upper : fallback;
};

const trimSlash = (url: string) => url.replace(/\/+$/, "");

interface Discovery {
  issuer?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  code_challenge_methods_supported?: string[];
}

interface Jwks {
  keys?: Array<Record<string, unknown> & { kid?: string; kty?: string }>;
}

interface HttpResult {
  status: number;
  ok: boolean;
  body: unknown;
}

const asRecord = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

const idpErrorDescription = (
  providerName: string,
  result: HttpResult,
): string => {
  const body = asRecord(result.body);
  const parts = [
    typeof body.error === "string" ? body.error : "",
    typeof body.error_description === "string" ? body.error_description : "",
  ].filter(Boolean);
  return `${providerName} Error - ${result.status}${parts.length ? ` ${parts.join(" ")}` : ""}`;
};

const idpError = (providerName: string, result: HttpResult) =>
  new RealIdpError(
    typeof asRecord(result.body).error === "string"
      ? (asRecord(result.body).error as string)
      : "invalid_request",
    idpErrorDescription(providerName, result),
  );

export function flattenClaims(source: Record<string, unknown>): Claims {
  const claims: Claims = {};
  for (const [name, value] of Object.entries(source)) {
    if (value === null || value === undefined) continue;
    claims[name] =
      typeof value === "object" ? JSON.stringify(value) : String(value);
  }
  return claims;
}

function applePrivateKey(value: string): string {
  if (value.includes("-----BEGIN")) return value.replace(/\\n/g, "\n");
  const body = value.replace(/\s+/g, "").replace(/(.{64})/g, "$1\n");
  return `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`;
}

const randomToken = () => randomBytes(32).toString("base64url");

export class RealIdp {
  private readonly cache = new Map<
    string,
    { expiresAt: number; value: unknown }
  >();

  constructor(private readonly clock: Clock) {}

  private async request(
    providerName: string,
    url: string,
    init: RequestInit,
  ): Promise<HttpResult> {
    let response: Response;
    try {
      response = await fetch(url, {
        ...init,
        redirect: "manual",
        signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
      });
    } catch (err) {
      throw new RealIdpError(
        "server_error",
        `${providerName} Error - could not reach ${new URL(url).origin}: ${(err as Error).message}`,
      );
    }
    const text = await response.text();
    let body: unknown = text;
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      body = text;
    }
    return { status: response.status, ok: response.ok, body };
  }

  private async getJson<T>(
    providerName: string,
    url: string,
    fresh = false,
  ): Promise<T> {
    const now = this.clock.get().getTime();
    const cached = this.cache.get(url);
    if (!fresh && cached && cached.expiresAt > now) return cached.value as T;
    const result = await this.request(providerName, url, {
      headers: { Accept: "application/json" },
    });
    if (!result.ok || typeof result.body !== "object") {
      throw idpError(providerName, result);
    }
    this.cache.set(url, {
      expiresAt: now + METADATA_TTL_MS,
      value: result.body,
    });
    return result.body as T;
  }

  async resolveEndpoints(
    provider: IdentityProviderConfig,
  ): Promise<RealEndpoints> {
    const details = provider.ProviderDetails ?? {};
    const defaults = socialDefaults(provider);
    const issuer = details.oidc_issuer
      ? trimSlash(details.oidc_issuer)
      : defaults.issuer;
    let authorizeUrl = details.authorize_url || defaults.authorizeUrl;
    let tokenUrl = details.token_url || defaults.tokenUrl;
    let attributesUrl = details.attributes_url || defaults.attributesUrl;
    let jwksUri = details.jwks_uri || undefined;
    let pkce = false;

    if (defaults.protocol === "oidc") {
      if (!issuer) {
        throw invalid(
          `Identity provider ${provider.ProviderName} has no oidc_issuer`,
        );
      }
      if (!authorizeUrl || !tokenUrl || !jwksUri) {
        const discovery = await this.getJson<Discovery>(
          provider.ProviderName,
          `${issuer}/.well-known/openid-configuration`,
        );
        authorizeUrl ||= discovery.authorization_endpoint;
        tokenUrl ||= discovery.token_endpoint;
        jwksUri ||= discovery.jwks_uri;
        attributesUrl ||= discovery.userinfo_endpoint;
        pkce = (discovery.code_challenge_methods_supported ?? []).includes(
          "S256",
        );
      }
    }
    if (!authorizeUrl || !tokenUrl) {
      throw invalid(
        `Identity provider ${provider.ProviderName} has no authorize_url or token_url`,
      );
    }
    if (defaults.protocol === "oidc" && !jwksUri) {
      throw invalid(
        `Identity provider ${provider.ProviderName} has no jwks_uri`,
      );
    }
    return {
      protocol: defaults.protocol,
      authorizeUrl,
      tokenUrl,
      tokenRequestMethod: httpMethod(
        details.token_request_method,
        defaults.tokenRequestMethod ?? "POST",
      ),
      attributesUrl,
      attributesRequestMethod: httpMethod(
        details.attributes_request_method,
        "GET",
      ),
      addAttributes:
        details.attributes_url_add_attributes !== undefined
          ? details.attributes_url_add_attributes === "true"
          : (defaults.addAttributes ?? false),
      jwksUri,
      issuer,
      pkce,
    };
  }

  async begin(
    provider: IdentityProviderConfig,
    redirectUri: string,
  ): Promise<RealSignIn> {
    const endpoints = await this.resolveEndpoints(provider);
    return {
      endpoints,
      redirectUri,
      nonce: endpoints.protocol === "oidc" ? randomToken() : undefined,
      codeVerifier: endpoints.pkce ? randomToken() : undefined,
    };
  }

  authorizeUrl(
    provider: IdentityProviderConfig,
    signIn: RealSignIn,
    state: string,
  ): string {
    const details = provider.ProviderDetails ?? {};
    const url = new URL(signIn.endpoints.authorizeUrl);
    const scope = details.authorize_scopes ?? "";
    const params: Record<string, string | undefined> = {
      response_type: "code",
      client_id: details.client_id ?? "",
      redirect_uri: signIn.redirectUri,
      scope,
      state,
      nonce: signIn.nonce,
      code_challenge: signIn.codeVerifier
        ? createHash("sha256").update(signIn.codeVerifier).digest("base64url")
        : undefined,
      code_challenge_method: signIn.codeVerifier ? "S256" : undefined,
      response_mode:
        provider.ProviderType === "SignInWithApple" &&
        /\b(name|email)\b/.test(scope)
          ? "form_post"
          : undefined,
    };
    for (const [name, value] of Object.entries(params)) {
      if (value !== undefined) url.searchParams.set(name, value);
    }
    return url.toString();
  }

  private clientSecret(provider: IdentityProviderConfig): string | undefined {
    const details = provider.ProviderDetails ?? {};
    if (details.client_secret) return details.client_secret;
    if (provider.ProviderType !== "SignInWithApple" || !details.private_key) {
      return undefined;
    }
    const now = Math.floor(this.clock.get().getTime() / 1000);
    return jwt.sign(
      {
        iss: details.team_id,
        iat: now,
        exp: now + 300,
        aud: details.oidc_issuer
          ? trimSlash(details.oidc_issuer)
          : "https://appleid.apple.com",
        sub: details.client_id,
      },
      applePrivateKey(details.private_key),
      { algorithm: "ES256", keyid: details.key_id },
    );
  }

  private async exchangeCode(
    provider: IdentityProviderConfig,
    signIn: RealSignIn,
    code: string,
  ): Promise<Record<string, unknown>> {
    const { endpoints } = signIn;
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: signIn.redirectUri,
      client_id: provider.ProviderDetails?.client_id ?? "",
    });
    const secret = this.clientSecret(provider);
    if (secret) params.set("client_secret", secret);
    if (signIn.codeVerifier) params.set("code_verifier", signIn.codeVerifier);

    let url = endpoints.tokenUrl;
    const init: RequestInit = { headers: { Accept: "application/json" } };
    if (endpoints.tokenRequestMethod === "GET") {
      const target = new URL(url);
      params.forEach((value, name) => target.searchParams.set(name, value));
      url = target.toString();
    } else {
      init.method = "POST";
      init.headers = {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      };
      init.body = params.toString();
    }
    const result = await this.request(provider.ProviderName, url, init);
    if (!result.ok) throw idpError(provider.ProviderName, result);
    const body = asRecord(result.body);
    if (typeof body.access_token !== "string" || !body.access_token) {
      throw invalid(
        `${provider.ProviderName} returned no access_token from its token endpoint`,
      );
    }
    return body;
  }

  private async signingKey(
    provider: IdentityProviderConfig,
    jwksUri: string,
    kid: string,
  ) {
    const find = (jwks: Jwks) => jwks.keys?.find((key) => key.kid === kid);
    let key = find(await this.getJson<Jwks>(provider.ProviderName, jwksUri));
    if (!key) {
      key = find(
        await this.getJson<Jwks>(provider.ProviderName, jwksUri, true),
      );
    }
    if (!key) {
      throw invalid(
        `Bad id_token: signing key ${kid} is not published at the jwks_uri of ${provider.ProviderName}`,
      );
    }
    try {
      return createPublicKey({ key: key as never, format: "jwk" });
    } catch {
      throw invalid(
        `Bad id_token: signing key ${kid} of ${provider.ProviderName} is not a valid public key`,
      );
    }
  }

  async verifyIdToken(
    provider: IdentityProviderConfig,
    signIn: RealSignIn,
    idToken: string,
  ): Promise<JwtPayload> {
    const { endpoints } = signIn;
    const decoded = jwt.decode(idToken, { complete: true });
    if (!decoded || typeof decoded.payload !== "object") {
      throw invalid("Bad id_token: not a JWT");
    }
    const alg = decoded.header.alg as Algorithm;
    if (!ID_TOKEN_ALGORITHMS.includes(alg)) {
      throw invalid(`Bad id_token: unsupported signing algorithm ${alg}`);
    }
    let key: Parameters<typeof jwt.verify>[1];
    if (alg.startsWith("HS")) {
      const secret = provider.ProviderDetails?.client_secret;
      if (!secret) {
        throw invalid(
          `Bad id_token: ${alg} needs the client_secret of ${provider.ProviderName}`,
        );
      }
      key = secret;
    } else {
      if (!decoded.header.kid) throw invalid("Bad id_token: no kid in header");
      key = await this.signingKey(
        provider,
        endpoints.jwksUri ?? "",
        decoded.header.kid,
      );
    }

    const issuers = [endpoints.issuer ?? ""];
    if (provider.ProviderType === "Google") issuers.push("accounts.google.com");
    let payload: JwtPayload;
    try {
      payload = jwt.verify(idToken, key, {
        algorithms: [alg],
        clockTimestamp: Math.floor(this.clock.get().getTime() / 1000),
      }) as JwtPayload;
    } catch (err) {
      const name = (err as Error).name;
      if (name === "TokenExpiredError") throw invalid("Bad id_token: expired");
      throw invalid(`Bad id_token: ${(err as Error).message}`);
    }
    if (!issuers.includes(String(payload.iss))) {
      throw invalid(`Bad id_token issuer ${payload.iss}`);
    }
    const clientId = provider.ProviderDetails?.client_id ?? "";
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!audiences.includes(clientId)) {
      throw invalid(`Bad id_token aud ${audiences.join(" ")}`);
    }
    if (typeof payload.exp !== "number") {
      throw invalid("Bad id_token: no exp claim");
    }
    if (signIn.nonce && payload.nonce !== signIn.nonce) {
      throw invalid("Bad id_token nonce");
    }
    return payload;
  }

  private async fetchAttributes(
    provider: IdentityProviderConfig,
    endpoints: RealEndpoints,
    accessToken: string,
  ): Promise<Record<string, unknown>> {
    let url = endpoints.attributesUrl ?? "";
    if (endpoints.addAttributes) {
      const subject = subjectClaimName(provider.ProviderType);
      const fields = [
        ...new Set([
          ...(provider.ProviderType === "Facebook" ? [subject] : []),
          ...Object.values(provider.AttributeMapping ?? {}),
        ]),
      ].filter(Boolean);
      url += fields.join(",");
    }
    const result = await this.request(provider.ProviderName, url, {
      method: endpoints.attributesRequestMethod,
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
    });
    if (!result.ok) throw idpError(provider.ProviderName, result);
    if (typeof result.body !== "object") {
      throw invalid(
        `${provider.ProviderName} returned a userInfo response that is not JSON`,
      );
    }
    return asRecord(result.body);
  }

  async complete(
    provider: IdentityProviderConfig,
    signIn: RealSignIn,
    code: string,
    appleUser?: string,
  ): Promise<Claims> {
    const { endpoints } = signIn;
    const tokens = await this.exchangeCode(provider, signIn, code);
    let claims: Claims = {};

    if (endpoints.protocol === "oidc") {
      if (typeof tokens.id_token !== "string") {
        throw invalid(
          `${provider.ProviderName} returned no id_token: include openid in authorize_scopes`,
        );
      }
      const payload = await this.verifyIdToken(
        provider,
        signIn,
        tokens.id_token,
      );
      claims = flattenClaims(payload);
    }

    if (endpoints.attributesUrl) {
      const attributes = flattenClaims(
        await this.fetchAttributes(
          provider,
          endpoints,
          tokens.access_token as string,
        ),
      );
      if (claims.sub && attributes.sub && attributes.sub !== claims.sub) {
        throw invalid(
          `${provider.ProviderName} userInfo sub does not match the id_token`,
        );
      }
      claims = { ...claims, ...attributes };
    }

    if (appleUser && provider.ProviderType === "SignInWithApple") {
      claims = { ...appleUserClaims(appleUser), ...claims };
    }
    return claims;
  }
}

function appleUserClaims(value: string): Claims {
  try {
    const user = asRecord(JSON.parse(value));
    const name = asRecord(user.name);
    const claims: Claims = {};
    if (typeof name.firstName === "string") claims.firstName = name.firstName;
    if (typeof name.lastName === "string") claims.lastName = name.lastName;
    const full = [claims.firstName, claims.lastName].filter(Boolean).join(" ");
    if (full) claims.name = full;
    if (typeof user.email === "string") claims.email = user.email;
    return claims;
  } catch {
    return {};
  }
}
