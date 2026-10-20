import bodyParser from "body-parser";
import express from "express";
import supertest from "supertest";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import * as TDB from "../__tests__/testDataBuilder";
import { UserLambdaValidationError } from "../errors";
import type { CognitoService, Triggers, UserPoolService } from "../services";
import type { User } from "../services/userPoolService";
import { AuthorizationCodeStore } from "./authorizationCodeStore";
import { attachOAuth2Routes } from "./routes";

const CALLBACK = "http://localhost:9999/cb";

describe("federated sign-in through the mock IdP", () => {
  let userPool: MockedObject<UserPoolService>;
  let cognito: MockedObject<CognitoService>;
  let triggers: MockedObject<Triggers>;
  let appClient: ReturnType<typeof TDB.appClient>;
  let codeStore: AuthorizationCodeStore;
  let app: express.Express;
  let saved: User[];

  beforeEach(() => {
    appClient = TDB.appClient({
      ClientId: "idp-client",
      UserPoolId: "us-east-1_fed",
      CallbackURLs: [CALLBACK],
      AllowedOAuthFlows: ["code"],
      AllowedOAuthScopes: ["openid", "email", "profile", "phone"],
      SupportedIdentityProviders: ["COGNITO", "Google"],
    });
    userPool = newMockUserPoolService({
      Id: "us-east-1_fed",
      _identityProviders: [
        {
          ProviderName: "Google",
          ProviderType: "Google",
          ProviderDetails: {
            client_id: "g-client",
            authorize_scopes: "openid email",
          },
          AttributeMapping: {
            email: "email",
            name: "name",
            custom: "<script>x</script>",
          },
        },
      ],
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
      } as any,
      codeStore,
    );
  });

  async function startFlow(): Promise<{ stateId: string; page: string }> {
    const authorize = await supertest(app).get("/oauth2/authorize").query({
      identity_provider: "Google",
      redirect_uri: CALLBACK,
      response_type: "CODE",
      client_id: "idp-client",
      scope: "openid email profile phone",
      state: "app-state",
    });
    expect(authorize.status).toBe(302);
    const location = new URL(authorize.header.location, "http://emulator");
    expect(location.pathname).toBe("/mock-idp/Google/authorize");
    expect(location.searchParams.get("client_id")).toBe("g-client");
    expect(location.searchParams.get("redirect_uri")).toMatch(
      /\/oauth2\/idpresponse$/,
    );
    const stateId = location.searchParams.get("state") ?? "";
    const page = await supertest(app).get(location.pathname + location.search);
    expect(page.status).toBe(200);
    return { stateId, page: page.text };
  }

  const respond = (fields: Record<string, string | string[]>) =>
    supertest(app)
      .post("/oauth2/idpresponse")
      .type("form")
      .send(
        new URLSearchParams(
          Object.entries(fields).flatMap(([k, v]) =>
            (Array.isArray(v) ? v : [v]).map((x) => [k, x]),
          ),
        ).toString(),
      );

  it("renders an escaped mock IdP form that posts to /oauth2/idpresponse", async () => {
    const { stateId, page } = await startFlow();
    expect(page).toContain('action="/oauth2/idpresponse"');
    expect(page).toContain(`name="state" value="${stateId}"`);
    expect(page).toContain('value="100000000000000000001"');
    expect(page).toContain("Simulate IdP error (access_denied)");
    expect(page).not.toContain("<script>x</script>");
    expect(page).toContain("&lt;script&gt;x&lt;/script&gt;");
  });

  it("creates the federated user and redirects with a code and the app state", async () => {
    const { stateId } = await startFlow();
    const res = await respond({
      state: stateId,
      subject: "1234",
      claim_name: ["email", "name"],
      claim_value: ["jane@gmail.com", "Jane"],
    });

    expect(res.status).toBe(302);
    const location = new URL(res.header.location);
    expect(location.origin + location.pathname).toBe(CALLBACK);
    expect(location.searchParams.get("state")).toBe("app-state");
    const stored = codeStore.consume(location.searchParams.get("code") ?? "");
    expect(stored).toMatchObject({
      clientId: "idp-client",
      username: "Google_1234",
      redirectUri: CALLBACK,
      scope: "openid email profile phone",
    });
    expect(saved[0].Username).toBe("Google_1234");
  });

  it("forwards an IdP error to the redirect_uri with the app state", async () => {
    const { stateId } = await startFlow();
    const res = await respond({
      state: stateId,
      error: "access_denied",
      error_description: "User cancelled the sign-in",
    });
    const location = new URL(res.header.location);
    expect(location.searchParams.get("error")).toBe("access_denied");
    expect(location.searchParams.get("error_description")).toBe(
      "User cancelled the sign-in",
    );
    expect(location.searchParams.get("state")).toBe("app-state");
    expect(userPool.saveUser).not.toHaveBeenCalled();
  });

  it("redirects invalid_request when PreSignUp blocks the user", async () => {
    triggers.enabled.mockImplementation((name) => name === "PreSignUp");
    triggers.preSignUp.mockRejectedValue(
      new UserLambdaValidationError("PreSignUp failed with error Not invited."),
    );
    const { stateId } = await startFlow();
    const res = await respond({ state: stateId, subject: "1234" });
    const location = new URL(res.header.location);
    expect(location.searchParams.get("error")).toBe("invalid_request");
    expect(location.searchParams.get("error_description")).toBe(
      "PreSignUp failed with error Not invited.",
    );
    expect(location.searchParams.get("state")).toBe("app-state");
  });

  it("rejects the response when the IdP was disabled on the client meanwhile", async () => {
    const { stateId } = await startFlow();
    cognito.getAppClient.mockResolvedValue({
      ...appClient,
      SupportedIdentityProviders: ["COGNITO"],
    });
    const res = await respond({ state: stateId, subject: "1234" });
    const location = new URL(res.header.location);
    expect(location.searchParams.get("error")).toBe("invalid_request");
    expect(location.searchParams.get("error_description")).toContain(
      "not enabled",
    );
  });

  it("accepts each state once", async () => {
    const { stateId } = await startFlow();
    await respond({ state: stateId, subject: "1234" });
    const replay = await respond({ state: stateId, subject: "1234" });
    expect(replay.status).toBe(400);
    const page = await supertest(app)
      .get("/mock-idp/Google/authorize")
      .query({ state: stateId });
    expect(page.status).toBe(400);
  });

  it("accepts an OIDC-style error on GET /oauth2/idpresponse", async () => {
    const { stateId } = await startFlow();
    const res = await supertest(app)
      .get("/oauth2/idpresponse")
      .query({ state: stateId, error: "access_denied" });
    const location = new URL(res.header.location);
    expect(location.searchParams.get("error")).toBe("access_denied");
    expect(location.searchParams.get("error_description")).toContain("Google");
  });
});
