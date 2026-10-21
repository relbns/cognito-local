import { describe, expect, it } from "vitest";
import * as TDB from "../__tests__/testDataBuilder";
import {
  buildErrorRedirect,
  decideAuthorize,
  decideClientCredentials,
  includesIdToken,
  isClientAuthenticated,
  parseClientCredentials,
  parseClientMetadata,
  parsePrompt,
  parseScopes,
} from "./oauthRequest";

const client = TDB.appClient({
  ClientId: "c1",
  CallbackURLs: ["http://localhost:9999/cb"],
  AllowedOAuthFlows: ["code"],
  AllowedOAuthScopes: ["openid", "email", "phone", "profile"],
  SupportedIdentityProviders: ["COGNITO", "Google"],
});
const providers = [
  { ProviderName: "Google" },
  { ProviderName: "ExampleOIDC", IdpIdentifiers: ["example-oidc"] },
];
const base = {
  client_id: "c1",
  redirect_uri: "http://localhost:9999/cb",
  response_type: "CODE",
  scope: "openid email profile phone",
};

describe("decideAuthorize", () => {
  it("accepts response_type in any case, without PKCE", () => {
    expect(decideAuthorize(base, client)).toEqual({
      kind: "login",
      responseType: "code",
      scopes: ["openid", "email", "profile", "phone"],
      codeChallenge: undefined,
      codeChallengeMethod: undefined,
    });
  });

  it("rejects without redirecting when the client or redirect_uri is invalid", () => {
    expect(decideAuthorize(base, null).kind).toBe("reject");
    expect(
      decideAuthorize({ ...base, redirect_uri: "http://evil.test" }, client)
        .kind,
    ).toBe("reject");
  });

  it.each([
    [{ response_type: undefined }, "invalid_request"],
    [{ response_type: "id_token" }, "unsupported_response_type"],
    [{ response_type: "token" }, "unauthorized_client"],
    [{ code_challenge: "x" }, "invalid_request"],
    [{ code_challenge_method: "S256" }, "invalid_request"],
    [
      { code_challenge: "x", code_challenge_method: "plain" },
      "invalid_request",
    ],
    [{ scope: "openid admin" }, "invalid_scope"],
    [{ scope: "email" }, "invalid_scope"],
    [{ identity_provider: "Nope" }, "invalid_request"],
    [{ identity_provider: "ExampleOIDC" }, "invalid_request"],
  ])("redirects with an error for %o", (overrides, error) => {
    expect(
      decideAuthorize({ ...base, ...overrides }, client, providers),
    ).toMatchObject({ kind: "redirectError", error });
  });

  it("keeps a valid S256 challenge", () => {
    expect(
      decideAuthorize(
        { ...base, code_challenge: "abc", code_challenge_method: "S256" },
        client,
      ),
    ).toMatchObject({ codeChallenge: "abc", codeChallengeMethod: "S256" });
  });

  it("grants all allowed scopes when none are requested", () => {
    expect(
      decideAuthorize({ ...base, scope: undefined }, client),
    ).toMatchObject({
      scopes: ["openid", "email", "phone", "profile"],
    });
  });

  it("does not validate scopes for a client without AllowedOAuthScopes", () => {
    const open = TDB.appClient({
      ClientId: "c1",
      CallbackURLs: ["http://localhost:9999/cb"],
    });
    expect(
      decideAuthorize({ ...base, scope: "openid custom" }, open),
    ).toMatchObject({
      kind: "login",
      scopes: ["openid", "custom"],
    });
  });

  it("treats COGNITO as the built-in login and a supported IdP as federated", () => {
    expect(
      decideAuthorize(
        { ...base, identity_provider: "COGNITO" },
        client,
        providers,
      ).kind,
    ).toBe("login");
    expect(
      decideAuthorize(
        { ...base, identity_provider: "Google" },
        client,
        providers,
      ),
    ).toMatchObject({
      kind: "federated",
      providerName: "Google",
      responseType: "code",
    });
  });

  it("resolves idp_identifier through IdpIdentifiers", () => {
    const withExampleOidc = {
      ...client,
      SupportedIdentityProviders: ["ExampleOIDC"],
    };
    expect(
      decideAuthorize(
        { ...base, idp_identifier: "example-oidc" },
        withExampleOidc,
        providers,
      ),
    ).toMatchObject({ kind: "federated", providerName: "ExampleOIDC" });
  });
});

describe("parseClientCredentials", () => {
  const header = `Basic ${Buffer.from("c1:sec").toString("base64")}`;

  it("reads client_secret_basic", () => {
    expect(parseClientCredentials(header, { client_id: "c1" })).toEqual({
      clientId: "c1",
      clientSecret: "sec",
      conflict: false,
    });
  });

  it("reads client_secret_post", () => {
    expect(
      parseClientCredentials(undefined, {
        client_id: "c1",
        client_secret: "sec",
      }),
    ).toEqual({ clientId: "c1", clientSecret: "sec", conflict: false });
  });

  it("flags a body client_id that differs from the header", () => {
    expect(parseClientCredentials(header, { client_id: "c2" }).conflict).toBe(
      true,
    );
  });
});

describe("helpers", () => {
  it("isClientAuthenticated requires the secret only for confidential clients", () => {
    expect(isClientAuthenticated({ ClientSecret: undefined }, undefined)).toBe(
      true,
    );
    expect(isClientAuthenticated({ ClientSecret: "s" }, "s")).toBe(true);
    expect(isClientAuthenticated({ ClientSecret: "s" }, undefined)).toBe(false);
  });

  it("parseScopes splits on spaces and plus signs and dedupes", () => {
    expect(parseScopes("openid+email openid")).toEqual(["openid", "email"]);
  });

  it("includesIdToken needs openid unless no scopes were recorded", () => {
    expect(includesIdToken([])).toBe(true);
    expect(includesIdToken(["openid"])).toBe(true);
    expect(includesIdToken(["aws.cognito.signin.user.admin"])).toBe(false);
  });

  it("buildErrorRedirect appends error, description and state", () => {
    const url = new URL(
      buildErrorRedirect(
        "http://localhost:9999/cb?x=1",
        "invalid_scope",
        "bad",
        "s1",
      ),
    );
    expect(Object.fromEntries(url.searchParams)).toEqual({
      x: "1",
      error: "invalid_scope",
      error_description: "bad",
      state: "s1",
    });
  });
});

describe("decideClientCredentials", () => {
  const servers = [
    {
      Identifier: "example.test",
      Scopes: [{ ScopeName: "read" }, { ScopeName: "write" }],
    },
    {
      Identifier: "https://api.example.test",
      Scopes: [{ ScopeName: "admin" }],
    },
  ];
  const client = (overrides = {}) => ({
    AllowedOAuthFlows: ["client_credentials" as const],
    AllowedOAuthFlowsUserPoolClient: true,
    AllowedOAuthScopes: ["example.test/read", "https://api.example.test/admin"],
    ...overrides,
  });

  it("grants every allowed custom scope when no scope is requested", () => {
    expect(decideClientCredentials(client(), undefined, servers)).toEqual({
      kind: "grant",
      scopes: ["example.test/read", "https://api.example.test/admin"],
    });
  });

  it("grants the requested scopes", () => {
    expect(
      decideClientCredentials(client(), "example.test/read", servers),
    ).toEqual({ kind: "grant", scopes: ["example.test/read"] });
  });

  it.each([
    ["the flow is not allowed", { AllowedOAuthFlows: ["code"] }],
    ["OAuth is off for the client", { AllowedOAuthFlowsUserPoolClient: false }],
    ["no flows are set", { AllowedOAuthFlows: undefined }],
  ])("refuses unauthorized_client when %s", (_, overrides) => {
    expect(
      decideClientCredentials(client(overrides), undefined, servers),
    ).toEqual({ kind: "error", error: "unauthorized_client" });
  });

  it.each([
    "example.test/delete",
    "other/read",
    "openid",
    "aws.cognito.signin.user.admin",
  ])("refuses invalid_scope for %s, which is not a custom scope", (scope) => {
    expect(decideClientCredentials(client(), scope, servers)).toEqual({
      kind: "error",
      error: "invalid_scope",
    });
  });

  it("refuses invalid_grant for a custom scope the client is not allowed", () => {
    expect(
      decideClientCredentials(
        client(),
        "example.test/read example.test/write",
        servers,
      ),
    ).toEqual({ kind: "error", error: "invalid_grant" });
  });

  it("refuses invalid_scope when the client has no custom scope", () => {
    expect(
      decideClientCredentials(
        client({ AllowedOAuthScopes: ["openid"] }),
        undefined,
        servers,
      ),
    ).toEqual({ kind: "error", error: "invalid_scope" });
  });
});

describe("parseClientMetadata", () => {
  it("reads a JSON object", () => {
    expect(parseClientMetadata('{"a":"1","b":2}')).toEqual({ a: "1", b: "2" });
  });

  it("is undefined when absent", () => {
    expect(parseClientMetadata(undefined)).toBeUndefined();
    expect(parseClientMetadata("")).toBeUndefined();
  });

  it.each(["not json", "[1]", "3", "null"])("is null for %s", (value) => {
    expect(parseClientMetadata(value)).toBeNull();
  });
});

describe("parsePrompt", () => {
  it("splits the values on spaces", () => {
    expect(parsePrompt("login consent")).toEqual(["login", "consent"]);
    expect(parsePrompt("none")).toEqual(["none"]);
    expect(parsePrompt(undefined)).toEqual([]);
    expect(parsePrompt(["none"])).toEqual([]);
  });
});

describe("buildErrorRedirect without a description", () => {
  it("leaves error_description out", () => {
    expect(
      buildErrorRedirect("http://localhost/cb", "login_required", "", "s"),
    ).toBe("http://localhost/cb?error=login_required&state=s");
  });
});
