import { describe, expect, it } from "vitest";
import * as TDB from "../__tests__/testDataBuilder";
import {
  buildErrorRedirect,
  decideAuthorize,
  includesIdToken,
  isClientAuthenticated,
  parseClientCredentials,
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
  { ProviderName: "examplesaml", IdpIdentifiers: ["tam"] },
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
    [{ identity_provider: "examplesaml" }, "invalid_request"],
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
    const withExampleSaml = { ...client, SupportedIdentityProviders: ["examplesaml"] };
    expect(
      decideAuthorize(
        { ...base, idp_identifier: "tam" },
        withExampleSaml,
        providers,
      ),
    ).toMatchObject({ kind: "federated", providerName: "examplesaml" });
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
