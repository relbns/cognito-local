import { generateKeyPairSync } from "node:crypto";
import bodyParser from "body-parser";
import express from "express";
import jwt from "jsonwebtoken";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  type MockedObject,
} from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { FakeOidcProvider } from "../__tests__/fakeOidcProvider";
import { localRequest } from "../__tests__/localRequest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import * as TDB from "../__tests__/testDataBuilder";
import type { FederationConfig } from "../server/config";
import type { CognitoService, Triggers, UserPoolService } from "../services";
import { attributeValue, type User } from "../services/userPoolService";
import { AuthorizationCodeStore } from "./authorizationCodeStore";
import type { IdentityProviderConfig } from "./federation";
import { attachOAuth2Routes } from "./routes";

const request = localRequest();

const CALLBACK = "http://localhost:9999/cb";
const CLIENT_ID = "corp-client";
const CLIENT_SECRET = "corp-secret";

describe("real OIDC federation", () => {
  const idp = new FakeOidcProvider({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    user: {
      sub: "corp-user-1",
      idTokenClaims: { name: "Jane Doe" },
      userInfo: { email: "jane@example.test", email_verified: true },
    },
  });
  let userPool: MockedObject<UserPoolService>;
  let cognito: MockedObject<CognitoService>;
  let triggers: MockedObject<Triggers>;
  let codeStore: AuthorizationCodeStore;
  let app: express.Express;
  let saved: User[];
  let providers: IdentityProviderConfig[];
  let federation: FederationConfig;

  beforeAll(async () => {
    await idp.start();
  });
  afterAll(async () => {
    await idp.stop();
  });

  const corpProvider = (
    details: Record<string, string> = {},
  ): IdentityProviderConfig => ({
    ProviderName: "CorpIdP",
    ProviderType: "OIDC",
    ProviderDetails: {
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      oidc_issuer: idp.issuer,
      authorize_scopes: "openid email profile",
      attributes_request_method: "GET",
      ...details,
    },
    AttributeMapping: { email: "email", name: "name", username: "sub" },
  });

  beforeEach(() => {
    idp.idTokenOverrides = {};
    idp.signingKey = undefined;
    idp.tokenError = undefined;
    idp.userInfoError = undefined;
    idp.omitIdToken = false;
    idp.requests.length = 0;
    idp.userInfoRequests.length = 0;
    providers = [corpProvider()];
    federation = { Mode: "real", Providers: {} };

    const appClient = TDB.appClient({
      ClientId: "web-client",
      UserPoolId: "us-east-1_real",
      CallbackURLs: [CALLBACK],
      AllowedOAuthFlows: ["code"],
      AllowedOAuthScopes: ["openid", "email", "profile"],
      SupportedIdentityProviders: [
        "COGNITO",
        "CorpIdP",
        "SocialIdP",
        "CorpSaml",
      ],
    });
    userPool = newMockUserPoolService({
      Id: "us-east-1_real",
      get _identityProviders() {
        return providers;
      },
    } as any);
    saved = [];
    userPool.listUsers.mockResolvedValue([]);
    userPool.getUserByUsername.mockResolvedValue(null);
    userPool.listUserGroupMembership.mockResolvedValue([]);
    userPool.saveUser.mockImplementation(async (_ctx, user) => {
      saved.push(user);
    });
    cognito = newMockCognitoService(userPool);
    cognito.getAppClient.mockResolvedValue(appClient);
    cognito.getUserPoolForClientId.mockResolvedValue(userPool);
    cognito.getUserPool.mockResolvedValue(userPool);
    triggers = newMockTriggers();
    triggers.enabled.mockReturnValue(false);

    app = express();
    app.use(bodyParser.urlencoded({ extended: false }));
    app.use((req, _res, next) => {
      (req as any).log = {
        child: () => (req as any).log,
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {},
      };
      next();
    });
    codeStore = new AuthorizationCodeStore();
    attachOAuth2Routes(
      app,
      {
        cognito,
        triggers,
        clock: new ClockFake(new Date()),
        tokenGenerator: newMockTokenGenerator(),
        config: { FederationConfig: federation } as any,
      } as any,
      codeStore,
    );
  });

  const authorize = (providerName = "CorpIdP") =>
    request(app).get("/oauth2/authorize").query({
      identity_provider: providerName,
      redirect_uri: CALLBACK,
      response_type: "code",
      client_id: "web-client",
      scope: "openid email profile",
      state: "app-state",
    });

  async function signIn(providerName = "CorpIdP") {
    const start = await authorize(providerName);
    expect(start.status).toBe(302);
    const toIdp = new URL(start.header.location);
    const fromIdp = await fetch(toIdp, { redirect: "manual" });
    expect(fromIdp.status).toBe(302);
    const back = new URL(fromIdp.headers.get("location") ?? "");
    const response = await request(app).get(back.pathname + back.search);
    return { toIdp, back, response };
  }

  const callbackParams = (res: { status: number; header: any }) => {
    expect(res.status).toBe(302);
    const location = new URL(res.header.location);
    expect(location.origin + location.pathname).toBe(CALLBACK);
    return location.searchParams;
  };

  it("redirects to the provider's authorize endpoint with state, nonce and PKCE", async () => {
    const res = await authorize();
    const location = new URL(res.header.location);
    expect(location.origin + location.pathname).toBe(`${idp.issuer}/authorize`);
    const params = location.searchParams;
    expect(params.get("client_id")).toBe(CLIENT_ID);
    expect(params.get("response_type")).toBe("code");
    expect(params.get("scope")).toBe("openid email profile");
    expect(params.get("redirect_uri")).toMatch(
      /^http:\/\/127\.0\.0\.1:\d+\/oauth2\/idpresponse$/,
    );
    expect(params.get("state")).toMatch(/^[0-9a-f-]{36}$/);
    expect(params.get("state")).not.toBe("app-state");
    expect(params.get("nonce")?.length).toBeGreaterThanOrEqual(32);
    expect(params.get("code_challenge_method")).toBe("S256");
    expect(params.get("code_challenge")).toBeTruthy();
  });

  it("exchanges the code, validates the id_token, reads userInfo and signs the user in", async () => {
    const { response } = await signIn();
    const params = callbackParams(response);
    expect(params.get("state")).toBe("app-state");
    expect(params.get("error")).toBeNull();
    expect(codeStore.consume(params.get("code") ?? "")).toMatchObject({
      clientId: "web-client",
      username: "CorpIdP_corp-user-1",
    });
    expect(saved[0].Username).toBe("CorpIdP_corp-user-1");
    expect(saved[0].UserStatus).toBe("EXTERNAL_PROVIDER");
    expect(attributeValue("email", saved[0].Attributes)).toBe(
      "jane@example.test",
    );
    expect(attributeValue("name", saved[0].Attributes)).toBe("Jane Doe");
    expect(
      JSON.parse(attributeValue("identities", saved[0].Attributes) ?? "[]"),
    ).toMatchObject([{ providerName: "CorpIdP", issuer: idp.issuer }]);

    const tokenRequest = idp.tokenRequests.at(-1);
    expect(tokenRequest?.get("client_secret")).toBe(CLIENT_SECRET);
    expect(tokenRequest?.get("code_verifier")).toBeTruthy();
    expect(idp.userInfoRequests.at(-1)?.method).toBe("GET");
  });

  it("caches discovery and JWKS, and refetches the JWKS for an unknown kid", async () => {
    await signIn();
    await signIn();
    expect(idp.count("/.well-known/openid-configuration")).toBe(1);
    expect(idp.count("/jwks")).toBe(1);

    const previousKid = idp.kid;
    idp.rotateKey("fake-key-2");
    const { response } = await signIn();
    expect(callbackParams(response).get("code")).toBeTruthy();
    expect(idp.count("/jwks")).toBe(2);
    idp.kid = previousKid;
  });

  it.each([
    [
      "a bad signature",
      () => {
        idp.signingKey = generateKeyPairSync("rsa", {
          modulusLength: 2048,
        }).privateKey;
      },
      "Bad id_token: invalid signature",
    ],
    [
      "a wrong audience",
      () => {
        idp.idTokenOverrides = { aud: "someone-else" };
      },
      "Bad id_token aud someone-else",
    ],
    [
      "a wrong issuer",
      () => {
        idp.idTokenOverrides = { iss: "https://other.example.test" };
      },
      "Bad id_token issuer https://other.example.test",
    ],
    [
      "an expired token",
      () => {
        const past = Math.floor(Date.now() / 1000) - 600;
        idp.idTokenOverrides = { iat: past - 300, exp: past };
      },
      "Bad id_token: expired",
    ],
    [
      "a nonce mismatch",
      () => {
        idp.idTokenOverrides = { nonce: "replayed-nonce" };
      },
      "Bad id_token nonce",
    ],
    [
      "no id_token",
      () => {
        idp.omitIdToken = true;
      },
      "CorpIdP returned no id_token: include openid in authorize_scopes",
    ],
    [
      "a userInfo sub that differs",
      () => {
        idp.options.user.userInfo = { sub: "someone-else" };
      },
      "CorpIdP userInfo sub does not match the id_token",
    ],
  ])(
    "rejects %s with invalid_request on the redirect_uri",
    async (_name, arrange, description) => {
      const userInfo = idp.options.user.userInfo;
      arrange();
      try {
        const { response } = await signIn();
        const params = callbackParams(response);
        expect(params.get("error")).toBe("invalid_request");
        expect(params.get("error_description")).toBe(description);
        expect(params.get("state")).toBe("app-state");
        expect(params.get("code")).toBeNull();
        expect(userPool.saveUser).not.toHaveBeenCalled();
      } finally {
        idp.options.user.userInfo = userInfo;
      }
    },
  );

  it("relays a token endpoint error with the provider name and HTTP status", async () => {
    idp.tokenError = {
      status: 400,
      body: { error: "invalid_grant", error_description: "Code expired" },
    };
    const { response } = await signIn();
    const params = callbackParams(response);
    expect(params.get("error")).toBe("invalid_grant");
    expect(params.get("error_description")).toBe(
      "CorpIdP Error - 400 invalid_grant Code expired",
    );
    expect(params.get("state")).toBe("app-state");
  });

  it("relays a userInfo error", async () => {
    idp.userInfoError = { status: 401, body: { error: "invalid_token" } };
    const params = callbackParams((await signIn()).response);
    expect(params.get("error")).toBe("invalid_token");
    expect(params.get("error_description")).toBe(
      "CorpIdP Error - 401 invalid_token",
    );
  });

  it("relays an error the provider sends back to /oauth2/idpresponse", async () => {
    const start = await authorize();
    const state = new URL(start.header.location).searchParams.get("state");
    const res = await request(app).get("/oauth2/idpresponse").query({
      state,
      error: "access_denied",
      error_description: "The user declined",
    });
    const params = callbackParams(res);
    expect(params.get("error")).toBe("access_denied");
    expect(params.get("error_description")).toBe("The user declined");
  });

  it("refuses a response with an unknown state, and a second use of a state", async () => {
    const { back, response } = await signIn();
    expect(callbackParams(response).get("code")).toBeTruthy();
    const replay = await request(app).get(back.pathname + back.search);
    expect(replay.status).toBe(400);
    const forged = await request(app)
      .get("/oauth2/idpresponse")
      .query({ state: "forged-state", code: "code-1" });
    expect(forged.status).toBe(400);
    expect(idp.tokenRequests.length).toBeGreaterThan(0);
  });

  it("does not accept mock IdP claims for a real sign-in", async () => {
    const start = await authorize();
    const state = new URL(start.header.location).searchParams.get("state");
    const page = await request(app)
      .get("/mock-idp/CorpIdP/authorize")
      .query({ state });
    expect(page.status).toBe(400);
    const posted = await request(app)
      .post("/oauth2/idpresponse")
      .type("form")
      .send({
        state,
        subject: "attacker",
        claim_name: "email",
        claim_value: "x@example.test",
      });
    const params = callbackParams(posted);
    expect(params.get("error")).toBe("invalid_request");
    expect(params.get("error_description")).toBe(
      "CorpIdP did not return an authorization code",
    );
    expect(userPool.saveUser).not.toHaveBeenCalled();
  });

  it("redirects an error to the app when discovery fails", async () => {
    providers = [corpProvider({ oidc_issuer: `${idp.issuer}/missing` })];
    const params = callbackParams(await authorize());
    expect(params.get("error")).toBe("invalid_request");
    expect(params.get("error_description")).toBe("CorpIdP Error - 404");
    expect(params.get("state")).toBe("app-state");
  });

  it("uses manual endpoints without discovery and skips PKCE", async () => {
    providers = [
      corpProvider({
        authorize_url: `${idp.issuer}/authorize`,
        token_url: `${idp.issuer}/token`,
        attributes_url: `${idp.issuer}/userinfo`,
        jwks_uri: `${idp.issuer}/jwks`,
        attributes_request_method: "POST",
      }),
    ];
    const { toIdp, response } = await signIn();
    expect(toIdp.searchParams.get("code_challenge")).toBeNull();
    expect(callbackParams(response).get("code")).toBeTruthy();
    expect(idp.count("/.well-known/openid-configuration")).toBe(0);
    expect(idp.userInfoRequests.at(-1)?.method).toBe("POST");
  });

  it("signs in through a plain OAuth 2.0 social provider with the token and attributes endpoints", async () => {
    providers = [
      {
        ProviderName: "SocialIdP",
        ProviderType: "Facebook",
        ProviderDetails: {
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          authorize_scopes: "public_profile,email",
          authorize_url: `${idp.issuer}/authorize`,
          token_url: `${idp.issuer}/token`,
          attributes_url: `${idp.issuer}/me?fields=`,
        },
        AttributeMapping: { email: "email", name: "name" },
      },
    ];
    const userInfo = idp.options.user.userInfo;
    idp.options.user.userInfo = {
      id: "fb-42",
      email: "fb@example.test",
      name: "Fb User",
    };
    try {
      const { toIdp, response } = await signIn("SocialIdP");
      expect(toIdp.searchParams.get("nonce")).toBeNull();
      expect(callbackParams(response).get("code")).toBeTruthy();
      expect(idp.tokenRequests.at(-1)?.get("grant_type")).toBe(
        "authorization_code",
      );
      expect(idp.userInfoRequests.at(-1)?.url).toBe("/me?fields=id,email,name");
      expect(saved[0].Username).toBe("SocialIdP_fb-42");
      expect(attributeValue("email", saved[0].Attributes)).toBe(
        "fb@example.test",
      );
    } finally {
      idp.options.user.userInfo = userInfo;
    }
  });

  describe("SignInWithApple", () => {
    const appleKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const apple = new FakeOidcProvider({
      clientId: "com.example.web",
      clientSecret: "",
      pkce: false,
      user: {
        sub: "000001.apple.0001",
        idTokenClaims: { email: "relay@example.test" },
      },
      acceptClientSecret: (secret) => {
        try {
          const claims = jwt.verify(secret ?? "", appleKey.publicKey, {
            algorithms: ["ES256"],
          }) as jwt.JwtPayload;
          return claims.iss === "TEAM123" && claims.sub === "com.example.web";
        } catch {
          return false;
        }
      },
    });
    beforeAll(async () => {
      await apple.start();
    });
    afterAll(async () => {
      await apple.stop();
    });

    it("signs the client secret with the private key and reads the posted user name", async () => {
      providers = [
        {
          ProviderName: "SocialIdP",
          ProviderType: "SignInWithApple",
          ProviderDetails: {
            client_id: "com.example.web",
            team_id: "TEAM123",
            key_id: "KEY123",
            private_key: appleKey.privateKey
              .export({ format: "pem", type: "pkcs8" })
              .toString(),
            authorize_scopes: "email name",
            oidc_issuer: apple.issuer,
          },
          AttributeMapping: {
            email: "email",
            given_name: "firstName",
            family_name: "lastName",
          },
        },
      ];
      const start = await authorize("SocialIdP");
      const toIdp = new URL(start.header.location);
      expect(toIdp.searchParams.get("response_mode")).toBe("form_post");
      const fromIdp = await fetch(toIdp, { redirect: "manual" });
      const back = new URL(fromIdp.headers.get("location") ?? "");
      const res = await request(app)
        .post("/oauth2/idpresponse")
        .type("form")
        .send({
          code: back.searchParams.get("code"),
          state: back.searchParams.get("state"),
          user: JSON.stringify({
            name: { firstName: "Jane", lastName: "Doe" },
          }),
        });
      expect(callbackParams(res).get("code")).toBeTruthy();
      const secret = jwt.decode(
        apple.tokenRequests.at(-1)?.get("client_secret") ?? "",
        { complete: true },
      );
      expect(secret?.header.kid).toBe("KEY123");
      expect(saved[0].Username).toBe("SocialIdP_000001.apple.0001");
      expect(attributeValue("given_name", saved[0].Attributes)).toBe("Jane");
      expect(attributeValue("family_name", saved[0].Attributes)).toBe("Doe");
      expect(attributeValue("email", saved[0].Attributes)).toBe(
        "relay@example.test",
      );
    });
  });

  describe("mode selection", () => {
    afterEach(() => {
      federation.Mode = "real";
      federation.Providers = {};
    });

    it("keeps the mock IdP when the global mode is mock", async () => {
      federation.Mode = "mock";
      const res = await authorize();
      expect(new URL(res.header.location, "http://x").pathname).toBe(
        "/mock-idp/CorpIdP/authorize",
      );
    });

    it("lets a provider override the global mode either way", async () => {
      federation.Mode = "mock";
      federation.Providers = { CorpIdP: { Mode: "real" } };
      const real = await authorize();
      expect(real.header.location).toMatch(
        /^http:\/\/127\.0\.0\.1:\d+\/authorize\?/,
      );

      federation.Mode = "real";
      federation.Providers = { CorpIdP: { Mode: "mock" } };
      const mock = await authorize();
      expect(mock.header.location).toMatch(/^\/mock-idp\/CorpIdP\/authorize\?/);
    });

    it("keeps the mock IdP for SAML providers in real mode", async () => {
      providers = [
        {
          ProviderName: "CorpSaml",
          ProviderType: "SAML",
          ProviderDetails: {
            MetadataURL: "https://saml.example.test/metadata",
          },
        },
      ];
      const res = await authorize("CorpSaml");
      expect(res.header.location).toMatch(/^\/mock-idp\/CorpSaml\/authorize\?/);
    });
  });
});
