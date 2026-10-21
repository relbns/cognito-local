import bodyParser from "body-parser";
import express from "express";
import type { MockedObject } from "vitest";
import { beforeEach, describe, expect, it } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { localRequest } from "../__tests__/localRequest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTokenVerifier } from "../__tests__/mockTokenVerifier";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import * as TDB from "../__tests__/testDataBuilder";
import { NotAuthorizedError } from "../errors";
import type { CognitoService, UserPoolService } from "../services";
import type { TokenGenerator } from "../services/tokenGenerator";
import { AuthorizationCodeStore } from "./authorizationCodeStore";
import { verifyS256 } from "./pkce";
import { attachOAuth2Routes } from "./routes";

const request = localRequest();

const buildApp = (
  cognito: MockedObject<CognitoService>,
  tokenGenerator: MockedObject<TokenGenerator>,
) => {
  const app = express();
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use((req, _res, next) => {
    // Attach a minimal pino-compatible logger to req
    (req as any).log = {
      child: () => (req as any).log,
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {},
    };
    next();
  });

  const codeStore = new AuthorizationCodeStore();
  const tokenVerifier = newMockTokenVerifier();
  tokenVerifier.verifyRefreshToken.mockImplementation(
    async (ctx, token, clientId) => {
      const userPool = await cognito.getUserPoolForClientId(ctx, clientId);
      const user = token
        ? await userPool.getUserByRefreshToken(ctx, token)
        : null;
      if (!user) throw new NotAuthorizedError("Invalid Refresh Token");
      return {
        token: token as string,
        claims: { "cognito:username": user.Username },
        user,
        userPool,
      };
    },
  );
  const triggers = newMockTriggers();
  triggers.enabled.mockReturnValue(false);
  attachOAuth2Routes(
    app,
    {
      clock: new ClockFake(new Date()),
      cognito,
      tokenGenerator,
      tokenVerifier,
      triggers,
    } as any,
    codeStore,
  );
  return { app, codeStore };
};

describe("OAuth2 routes", () => {
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockCognito: MockedObject<CognitoService>;
  let mockTokenGenerator: MockedObject<TokenGenerator>;
  let appClient: ReturnType<typeof TDB.appClient>;
  let user: ReturnType<typeof TDB.user>;

  beforeEach(() => {
    appClient = TDB.appClient({
      ClientId: "test-client-id",
      UserPoolId: "us-east-1_test",
      CallbackURLs: ["http://localhost:9876"],
      AllowedOAuthFlows: ["code"],
      AllowedOAuthScopes: ["openid", "email", "profile"],
    });
    user = TDB.user({
      Username: "testuser",
      Password: "Password123!",
      UserStatus: "CONFIRMED",
    });

    mockUserPoolService = newMockUserPoolService({ Id: "us-east-1_test" });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
    mockUserPoolService.storeRefreshToken.mockResolvedValue(undefined);

    mockCognito = newMockCognitoService(mockUserPoolService);
    mockCognito.getAppClient.mockResolvedValue(appClient);
    mockCognito.getUserPoolForClientId.mockResolvedValue(mockUserPoolService);
    mockCognito.getUserPool.mockResolvedValue(mockUserPoolService);

    mockTokenGenerator = newMockTokenGenerator();
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "access-token",
      IdToken: "id-token",
      RefreshToken: "refresh-token",
      ExpiresIn: 3600,
      TokenType: "Bearer",
    });
  });

  describe("GET /oauth2/authorize", () => {
    it("returns 400 if client_id is missing", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app).get("/oauth2/authorize").query({
        redirect_uri: "http://localhost:9876",
        response_type: "code",
        code_challenge: "abc",
        code_challenge_method: "S256",
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("invalid_request");
    });

    it("redirects unauthorized_client when the client does not allow the implicit flow", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app).get("/oauth2/authorize").query({
        client_id: "test-client-id",
        redirect_uri: "http://localhost:9876",
        response_type: "token",
        code_challenge: "abc",
        code_challenge_method: "S256",
      });
      expect(res.status).toBe(302);
      const location = new URL(res.header.location);
      expect(location.origin).toBe("http://localhost:9876");
      expect(location.searchParams.get("error")).toBe("unauthorized_client");
    });

    it("redirects invalid_request if code_challenge_method is not S256", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app).get("/oauth2/authorize").query({
        client_id: "test-client-id",
        redirect_uri: "http://localhost:9876",
        response_type: "code",
        code_challenge: "abc",
        code_challenge_method: "plain",
        state: "s1",
      });
      expect(res.status).toBe(302);
      const location = new URL(res.header.location);
      expect(location.searchParams.get("error")).toBe("invalid_request");
      expect(location.searchParams.get("state")).toBe("s1");
    });

    it("returns 400 if redirect_uri is not registered", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app).get("/oauth2/authorize").query({
        client_id: "test-client-id",
        redirect_uri: "http://evil.com/callback",
        response_type: "code",
        code_challenge: "abc",
        code_challenge_method: "S256",
      });
      expect(res.status).toBe(400);
    });

    it("returns 400 if client_id does not exist", async () => {
      mockCognito.getAppClient.mockResolvedValue(null);
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app).get("/oauth2/authorize").query({
        client_id: "unknown-client",
        redirect_uri: "http://localhost:9876",
        response_type: "code",
        code_challenge: "abc",
        code_challenge_method: "S256",
      });
      expect(res.status).toBe(400);
    });

    it("returns HTML login form for valid request", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app).get("/oauth2/authorize").query({
        client_id: "test-client-id",
        redirect_uri: "http://localhost:9876",
        response_type: "code",
        code_challenge: "challenge123",
        code_challenge_method: "S256",
        scope: "openid email",
        state: "my-state",
      });
      expect(res.status).toBe(200);
      expect(res.type).toMatch(/html/);
      expect(res.text).toContain("<form");
      expect(res.text).toContain('name="username"');
      expect(res.text).toContain('name="password"');
      expect(res.text).toContain("challenge123");
      expect(res.text).toContain("my-state");
    });
  });

  describe("POST /oauth2/authorize", () => {
    const validFormData = {
      client_id: "test-client-id",
      redirect_uri: "http://localhost:9876",
      response_type: "code",
      code_challenge: "challenge123",
      code_challenge_method: "S256",
      scope: "openid email",
      state: "my-state",
      username: "testuser",
      password: "Password123!",
    };

    it("redirects with code and state on valid credentials", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/authorize")
        .type("form")
        .send(validFormData);
      expect(res.status).toBe(302);
      const location = new URL(res.header.location);
      expect(location.hostname).toBe("localhost");
      expect(location.port).toBe("9876");
      expect(location.searchParams.get("state")).toBe("my-state");
      expect(location.searchParams.get("code")).toBeTruthy();
    });

    it("shows login form with error on wrong password", async () => {
      mockUserPoolService.getUserByUsername.mockResolvedValue({
        ...user,
        Password: "different-password",
      });
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/authorize")
        .type("form")
        .send(validFormData);
      expect(res.status).toBe(200);
      expect(res.text).toContain("Incorrect username or password");
    });

    it("shows login form with error when user not found", async () => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(null);
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/authorize")
        .type("form")
        .send(validFormData);
      expect(res.status).toBe(200);
      expect(res.text).toContain("User does not exist.");
    });

    it("shows login form with error for unconfirmed user", async () => {
      mockUserPoolService.getUserByUsername.mockResolvedValue({
        ...user,
        UserStatus: "UNCONFIRMED",
      });
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/authorize")
        .type("form")
        .send(validFormData);
      expect(res.status).toBe(200);
      expect(res.text).toContain("User is not confirmed.");
    });

    it("returns 400 if redirect_uri not registered", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/authorize")
        .type("form")
        .send({ ...validFormData, redirect_uri: "http://evil.com" });
      expect(res.status).toBe(400);
    });
  });

  describe("POST /oauth2/token grant_type=client_credentials", () => {
    const basic = (id: string, secret: string) =>
      `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;

    beforeEach(() => {
      appClient = TDB.appClient({
        ClientId: "m2m",
        ClientSecret: "m2m-secret",
        UserPoolId: "us-east-1_test",
        AllowedOAuthFlows: ["client_credentials"],
        AllowedOAuthFlowsUserPoolClient: true,
        AllowedOAuthScopes: ["example.test/read"],
      });
      mockCognito.getAppClient.mockResolvedValue(appClient);
      (mockUserPoolService.options as any)._resourceServers = [
        { Identifier: "example.test", Scopes: [{ ScopeName: "read" }] },
      ];
    });

    it("returns an access token only", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/token")
        .set("Authorization", basic("m2m", "m2m-secret"))
        .type("form")
        .send({
          grant_type: "client_credentials",
          scope: "example.test/read",
          aws_client_metadata: '{"ip":"192.0.2.1"}',
        });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        access_token: "access",
        expires_in: 3600,
        token_type: "Bearer",
      });
      expect(mockTokenGenerator.generateClientCredentials).toHaveBeenCalledWith(
        expect.anything(),
        appClient,
        ["example.test/read"],
        { ip: "192.0.2.1" },
      );
    });

    it("accepts the secret in the body", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app).post("/oauth2/token").type("form").send({
        grant_type: "client_credentials",
        client_id: "m2m",
        client_secret: "m2m-secret",
      });

      expect(res.status).toBe(200);
    });

    it.each([
      ["a wrong secret", { client_id: "m2m", client_secret: "wrong" }],
      ["no secret", { client_id: "m2m" }],
    ])("refuses invalid_client for %s", async (_, credentials) => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/token")
        .type("form")
        .send({ grant_type: "client_credentials", ...credentials });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe("invalid_client");
    });

    it("refuses invalid_client for a client without a secret", async () => {
      mockCognito.getAppClient.mockResolvedValue({
        ...appClient,
        ClientSecret: undefined,
      });
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/token")
        .type("form")
        .send({ grant_type: "client_credentials", client_id: "m2m" });

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: "invalid_client" });
    });

    it.each([
      ["unauthorized_client", { AllowedOAuthFlows: ["code"] }, undefined],
      ["invalid_scope", {}, "example.test/write"],
      [
        "invalid_grant",
        { AllowedOAuthScopes: ["openid"] },
        "example.test/read",
      ],
    ])("refuses %s", async (error, overrides, scope) => {
      mockCognito.getAppClient.mockResolvedValue({
        ...appClient,
        ...(overrides as Partial<typeof appClient>),
      });
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/token")
        .set("Authorization", basic("m2m", "m2m-secret"))
        .type("form")
        .send({
          grant_type: "client_credentials",
          ...(scope ? { scope } : {}),
        });

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error });
      expect(
        mockTokenGenerator.generateClientCredentials,
      ).not.toHaveBeenCalled();
    });

    it("refuses aws_client_metadata that is not a JSON object", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/token")
        .set("Authorization", basic("m2m", "m2m-secret"))
        .type("form")
        .send({ grant_type: "client_credentials", aws_client_metadata: "[1]" });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe("invalid_request");
    });
  });

  describe("POST /oauth2/token", () => {
    describe("grant_type=authorization_code", () => {
      it("exchanges a valid code for tokens", async () => {
        const { app, codeStore } = buildApp(mockCognito, mockTokenGenerator);

        const code = codeStore.create({
          clientId: "test-client-id",
          userPoolId: "us-east-1_test",
          username: "testuser",
          redirectUri: "http://localhost:9876",
          codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
          scope: "openid email",
          state: "my-state",
        });

        const res = await request(app).post("/oauth2/token").type("form").send({
          grant_type: "authorization_code",
          code,
          redirect_uri: "http://localhost:9876",
          client_id: "test-client-id",
          // Verifier that produces the challenge above
          code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        });

        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({
          access_token: "access-token",
          id_token: "id-token",
          refresh_token: "refresh-token",
          token_type: "Bearer",
          expires_in: 3600,
        });
      });

      it("returns 400 for expired or unknown code", async () => {
        const { app } = buildApp(mockCognito, mockTokenGenerator);
        const res = await request(app).post("/oauth2/token").type("form").send({
          grant_type: "authorization_code",
          code: "nonexistent-code",
          redirect_uri: "http://localhost:9876",
          client_id: "test-client-id",
          code_verifier: "some-verifier",
        });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe("invalid_grant");
      });

      it("returns 400 when code_verifier does not match code_challenge", async () => {
        const { app, codeStore } = buildApp(mockCognito, mockTokenGenerator);
        const code = codeStore.create({
          clientId: "test-client-id",
          userPoolId: "us-east-1_test",
          username: "testuser",
          redirectUri: "http://localhost:9876",
          codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
          scope: "openid",
          state: undefined,
        });

        const res = await request(app).post("/oauth2/token").type("form").send({
          grant_type: "authorization_code",
          code,
          redirect_uri: "http://localhost:9876",
          client_id: "test-client-id",
          code_verifier: "wrong-verifier",
        });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe("invalid_grant");
      });

      it("returns unauthorized_client when redirect_uri does not match stored value", async () => {
        const { app, codeStore } = buildApp(mockCognito, mockTokenGenerator);
        const code = codeStore.create({
          clientId: "test-client-id",
          userPoolId: "us-east-1_test",
          username: "testuser",
          redirectUri: "http://localhost:9876",
          codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
          scope: "openid",
          state: undefined,
        });

        const res = await request(app).post("/oauth2/token").type("form").send({
          grant_type: "authorization_code",
          code,
          redirect_uri: "http://localhost:9999",
          client_id: "test-client-id",
          code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        });
        expect(res.status).toBe(400);
        expect(res.body).toEqual({
          error: "unauthorized_client",
          error_description: "invalid_redirect",
        });
      });

      it("invalidates the code after first use", async () => {
        const { app, codeStore } = buildApp(mockCognito, mockTokenGenerator);
        const code = codeStore.create({
          clientId: "test-client-id",
          userPoolId: "us-east-1_test",
          username: "testuser",
          redirectUri: "http://localhost:9876",
          codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
          scope: "openid",
          state: undefined,
        });

        const body = {
          grant_type: "authorization_code",
          code,
          redirect_uri: "http://localhost:9876",
          client_id: "test-client-id",
          code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        };

        const first = await request(app)
          .post("/oauth2/token")
          .type("form")
          .send(body);
        expect(first.status).toBe(200);

        const second = await request(app)
          .post("/oauth2/token")
          .type("form")
          .send(body);
        expect(second.status).toBe(400);
        expect(second.body.error).toBe("invalid_grant");
      });
    });

    describe("grant_type=refresh_token", () => {
      it("exchanges a refresh token for new access and id tokens", async () => {
        mockUserPoolService.getUserByRefreshToken.mockResolvedValue(user);
        const { app } = buildApp(mockCognito, mockTokenGenerator);

        const res = await request(app).post("/oauth2/token").type("form").send({
          grant_type: "refresh_token",
          refresh_token: "some-refresh-token",
          client_id: "test-client-id",
        });

        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({
          access_token: "access-token",
          id_token: "id-token",
          token_type: "Bearer",
          expires_in: 3600,
        });
        expect(res.body.refresh_token).toBeUndefined();
      });

      it("returns 400 for invalid refresh token", async () => {
        mockUserPoolService.getUserByRefreshToken.mockResolvedValue(null);
        const { app } = buildApp(mockCognito, mockTokenGenerator);

        const res = await request(app).post("/oauth2/token").type("form").send({
          grant_type: "refresh_token",
          refresh_token: "bad-token",
          client_id: "test-client-id",
        });

        expect(res.status).toBe(400);
        expect(res.body.error).toBe("invalid_grant");
      });
    });

    it("returns 400 for unsupported grant_type", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/token")
        .type("form")
        .send({ grant_type: "password" });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("unsupported_grant_type");
    });
  });
});

describe("PKCE verifyS256", () => {
  it("returns true for a valid code_verifier / code_challenge pair", () => {
    // RFC 7636 Appendix B test vector
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    expect(verifyS256(verifier, challenge)).toBe(true);
  });

  it("returns false for a wrong verifier", () => {
    const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    expect(verifyS256("wrong-verifier", challenge)).toBe(false);
  });
});

describe("AuthorizationCodeStore", () => {
  it("creates and consumes a code", () => {
    const store = new AuthorizationCodeStore();
    const data = {
      clientId: "c1",
      userPoolId: "p1",
      username: "u1",
      redirectUri: "http://localhost",
      codeChallenge: "ch",
      scope: "openid",
      state: "s1",
    };
    const code = store.create(data);
    expect(code).toBeTruthy();
    expect(store.consume(code)).toEqual(data);
  });

  it("returns null for unknown code", () => {
    const store = new AuthorizationCodeStore();
    expect(store.consume("nonexistent")).toBeNull();
  });

  it("returns null when code is consumed a second time", () => {
    const store = new AuthorizationCodeStore();
    const code = store.create({
      clientId: "c1",
      userPoolId: "p1",
      username: "u1",
      redirectUri: "http://localhost",
      codeChallenge: "ch",
      scope: "openid",
      state: undefined,
    });
    store.consume(code);
    expect(store.consume(code)).toBeNull();
  });
});

describe("OAuth2 routes: Cognito request compatibility", () => {
  const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
  const basic = (id: string, secret: string) =>
    `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;

  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockCognito: MockedObject<CognitoService>;
  let mockTokenGenerator: MockedObject<TokenGenerator>;
  let appClient: ReturnType<typeof TDB.appClient>;

  beforeEach(() => {
    appClient = TDB.appClient({
      ClientId: "conf-client",
      ClientSecret: "s3cret",
      UserPoolId: "us-east-1_test",
      CallbackURLs: ["http://localhost:9999/cb"],
      AllowedOAuthFlows: ["code", "implicit"],
      AllowedOAuthScopes: ["email", "openid", "phone", "profile"],
      SupportedIdentityProviders: ["COGNITO", "Google"],
    });
    mockUserPoolService = newMockUserPoolService({
      Id: "us-east-1_test",
      _identityProviders: [
        { ProviderName: "Google", ProviderType: "Google" },
        { ProviderName: "ExampleOIDC", ProviderType: "OIDC" },
      ],
    } as any);
    mockUserPoolService.getUserByUsername.mockResolvedValue(
      TDB.user({ Username: "u1", Password: "Pw1!", UserStatus: "CONFIRMED" }),
    );
    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
    mockUserPoolService.storeRefreshToken.mockResolvedValue(undefined);
    mockCognito = newMockCognitoService(mockUserPoolService);
    mockCognito.getAppClient.mockResolvedValue(appClient);
    mockCognito.getUserPoolForClientId.mockResolvedValue(mockUserPoolService);
    mockCognito.getUserPool.mockResolvedValue(mockUserPoolService);
    mockTokenGenerator = newMockTokenGenerator();
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "access-token",
      IdToken: "id-token",
      RefreshToken: "refresh-token",
      ExpiresIn: 3600,
      TokenType: "Bearer",
    });
  });

  const confidentialClientQuery = {
    redirect_uri: "http://localhost:9999/cb",
    response_type: "CODE",
    client_id: "conf-client",
    scope: "openid email profile phone",
    state: "s1",
  };

  describe("GET /oauth2/authorize", () => {
    it("accepts upper-case response_type=CODE without PKCE", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .get("/oauth2/authorize")
        .query(confidentialClientQuery);
      expect(res.status).toBe(200);
      expect(res.text).toContain('name="response_type" value="code"');
      expect(res.text).not.toContain('name="code_challenge"');
    });

    it("shows the built-in login for identity_provider=COGNITO", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .get("/oauth2/authorize")
        .query({ ...confidentialClientQuery, identity_provider: "COGNITO" });
      expect(res.status).toBe(200);
      expect(res.text).toContain('name="password"');
    });

    it("redirects a configured federated identity provider to the mock IdP", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .get("/oauth2/authorize")
        .query({ ...confidentialClientQuery, identity_provider: "Google" });
      expect(res.status).toBe(302);
      const location = new URL(res.header.location, "http://emulator");
      expect(location.pathname).toBe("/mock-idp/Google/authorize");
      expect(location.searchParams.get("state")).toBeTruthy();
      expect(location.searchParams.get("state")).not.toBe("s1");
    });

    it("redirects invalid_request for an identity provider not enabled for the client", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .get("/oauth2/authorize")
        .query({
          ...confidentialClientQuery,
          identity_provider: "ExampleOIDC",
        });
      expect(res.status).toBe(302);
      const location = new URL(res.header.location);
      expect(location.searchParams.get("error")).toBe("invalid_request");
      expect(location.searchParams.get("error_description")).toContain(
        "not enabled",
      );
      expect(location.searchParams.get("state")).toBe("s1");
    });

    it("redirects invalid_request for an unknown identity provider", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .get("/oauth2/authorize")
        .query({ ...confidentialClientQuery, identity_provider: "Nope" });
      expect(res.status).toBe(302);
      expect(
        new URL(res.header.location).searchParams.get("error_description"),
      ).toContain("not configured");
    });

    it("redirects invalid_scope for a scope the client does not allow", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .get("/oauth2/authorize")
        .query({ ...confidentialClientQuery, scope: "openid admin:all" });
      expect(res.status).toBe(302);
      expect(new URL(res.header.location).searchParams.get("error")).toBe(
        "invalid_scope",
      );
    });

    it("redirects unsupported_response_type for an unknown response_type", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .get("/oauth2/authorize")
        .query({ ...confidentialClientQuery, response_type: "id_token" });
      expect(res.status).toBe(302);
      expect(new URL(res.header.location).searchParams.get("error")).toBe(
        "unsupported_response_type",
      );
    });
  });

  describe("POST /oauth2/authorize", () => {
    it("issues a code without PKCE and keeps the granted scopes", async () => {
      const { app, codeStore } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/authorize")
        .type("form")
        .send({
          ...confidentialClientQuery,
          response_type: "code",
          username: "u1",
          password: "Pw1!",
        });
      expect(res.status).toBe(302);
      const code = new URL(res.header.location).searchParams.get("code")!;
      expect(codeStore.consume(code)).toMatchObject({
        codeChallenge: undefined,
        scope: "openid email profile phone",
      });
    });

    it("returns tokens in the fragment for response_type=token", async () => {
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/authorize")
        .type("form")
        .send({
          ...confidentialClientQuery,
          response_type: "token",
          scope: "openid email",
          username: "u1",
          password: "Pw1!",
        });
      expect(res.status).toBe(302);
      const location = new URL(res.header.location);
      const fragment = new URLSearchParams(location.hash.slice(1));
      expect(location.search).toBe("");
      expect(fragment.get("access_token")).toBe("access-token");
      expect(fragment.get("id_token")).toBe("id-token");
      expect(fragment.get("state")).toBe("s1");
      expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        [],
        appClient,
        undefined,
        "HostedAuth",
        ["openid", "email"],
      );
    });
  });

  describe("POST /oauth2/token", () => {
    const codeFor = (
      codeStore: AuthorizationCodeStore,
      overrides: Partial<Parameters<AuthorizationCodeStore["create"]>[0]> = {},
    ) =>
      codeStore.create({
        clientId: "conf-client",
        userPoolId: "us-east-1_test",
        username: "u1",
        redirectUri: "http://localhost:9999/cb",
        codeChallenge: undefined,
        scope: "openid email profile phone",
        state: "s1",
        ...overrides,
      });

    const confidentialTokenBody = (code: string) => ({
      grant_type: "authorization_code",
      client_id: "conf-client",
      redirect_uri: "http://localhost:9999/cb",
      code,
    });

    it("accepts the client secret in HTTP Basic auth, without PKCE", async () => {
      const { app, codeStore } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/token")
        .set("Authorization", basic("conf-client", "s3cret"))
        .type("form")
        .send(confidentialTokenBody(codeFor(codeStore)));
      expect(res.status).toBe(200);
      expect(res.body.id_token).toBe("id-token");
      expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        [],
        appClient,
        undefined,
        "HostedAuth",
        ["openid", "email", "profile", "phone"],
      );
    });

    it("accepts client_id and client_secret in the body", async () => {
      const { app, codeStore } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/token")
        .type("form")
        .send({
          ...confidentialTokenBody(codeFor(codeStore)),
          client_secret: "s3cret",
        });
      expect(res.status).toBe(200);
    });

    it("returns invalid_client for a wrong secret", async () => {
      const { app, codeStore } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/token")
        .set("Authorization", basic("conf-client", "wrong"))
        .type("form")
        .send(confidentialTokenBody(codeFor(codeStore)));
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("invalid_client");
    });

    it("returns invalid_client when a confidential client sends no secret", async () => {
      const { app, codeStore } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/token")
        .type("form")
        .send(confidentialTokenBody(codeFor(codeStore)));
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("invalid_client");
    });

    it("returns invalid_client when the body client_id differs from the Basic one", async () => {
      const { app, codeStore } = buildApp(mockCognito, mockTokenGenerator);
      const res = await request(app)
        .post("/oauth2/token")
        .set("Authorization", basic("conf-client", "s3cret"))
        .type("form")
        .send({
          ...confidentialTokenBody(codeFor(codeStore)),
          client_id: "other",
        });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("invalid_client");
    });

    it("requires code_verifier when the code was issued with a code_challenge", async () => {
      const { app, codeStore } = buildApp(mockCognito, mockTokenGenerator);
      const code = codeFor(codeStore, { codeChallenge: CHALLENGE });
      const res = await request(app)
        .post("/oauth2/token")
        .set("Authorization", basic("conf-client", "s3cret"))
        .type("form")
        .send(confidentialTokenBody(code));
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("invalid_grant");
    });

    it("accepts the matching code_verifier for a PKCE code", async () => {
      const { app, codeStore } = buildApp(mockCognito, mockTokenGenerator);
      const code = codeFor(codeStore, { codeChallenge: CHALLENGE });
      const res = await request(app)
        .post("/oauth2/token")
        .set("Authorization", basic("conf-client", "s3cret"))
        .type("form")
        .send({ ...confidentialTokenBody(code), code_verifier: VERIFIER });
      expect(res.status).toBe(200);
    });

    it("omits the id_token when openid was not granted", async () => {
      const { app, codeStore } = buildApp(mockCognito, mockTokenGenerator);
      const code = codeFor(codeStore, {
        scope: "aws.cognito.signin.user.admin",
      });
      const res = await request(app)
        .post("/oauth2/token")
        .set("Authorization", basic("conf-client", "s3cret"))
        .type("form")
        .send(confidentialTokenBody(code));
      expect(res.status).toBe(200);
      expect(res.body.id_token).toBeUndefined();
      expect(res.body.access_token).toBe("access-token");
    });

    it("authenticates the client on refresh_token grants too", async () => {
      mockUserPoolService.getUserByRefreshToken.mockResolvedValue(
        TDB.user({ Username: "u1" }),
      );
      const { app } = buildApp(mockCognito, mockTokenGenerator);
      const body = {
        grant_type: "refresh_token",
        client_id: "conf-client",
        refresh_token: "refresh-token",
      };
      const unauthed = await request(app)
        .post("/oauth2/token")
        .type("form")
        .send(body);
      expect(unauthed.body.error).toBe("invalid_client");
      const authed = await request(app)
        .post("/oauth2/token")
        .set("Authorization", basic("conf-client", "s3cret"))
        .type("form")
        .send(body);
      expect(authed.status).toBe(200);
    });
  });
});
