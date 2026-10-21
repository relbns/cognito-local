import bodyParser from "body-parser";
import express from "express";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { localRequest } from "../__tests__/localRequest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import * as TDB from "../__tests__/testDataBuilder";
import { UserLambdaValidationError } from "../errors";
import type { FederationConfig } from "../server/config";
import type { CognitoService, Triggers, UserPoolService } from "../services";
import type { User } from "../services/userPoolService";
import { AuthorizationCodeStore } from "./authorizationCodeStore";
import { REMEMBERED_ACCOUNTS_COOKIE } from "./mockIdpAccounts";
import { attachOAuth2Routes } from "./routes";

const request = localRequest();

const CALLBACK = "http://localhost:9999/cb";

describe("federated sign-in through the mock IdP", () => {
  let userPool: MockedObject<UserPoolService>;
  let cognito: MockedObject<CognitoService>;
  let triggers: MockedObject<Triggers>;
  let appClient: ReturnType<typeof TDB.appClient>;
  let codeStore: AuthorizationCodeStore;
  let app: express.Express;
  let saved: User[];
  let services: Record<string, unknown>;

  beforeEach(() => {
    appClient = TDB.appClient({
      ClientId: "idp-client",
      UserPoolId: "us-east-1_fed",
      CallbackURLs: [CALLBACK],
      AllowedOAuthFlows: ["code"],
      AllowedOAuthScopes: ["openid", "email", "profile", "phone"],
      SupportedIdentityProviders: ["COGNITO", "Google", "Corp"],
      ClientName: "example-web",
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
            given_name: "given_name",
            custom: "<script>x</script>",
          },
        },
        {
          ProviderName: "Corp",
          ProviderType: "OIDC",
          ProviderDetails: {
            client_id: "corp-client",
            oidc_issuer: "https://login.example.test",
          },
          AttributeMapping: { email: "mail", username: "sub" },
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
    services = {
      cognito,
      triggers,
      clock: new ClockFake(new Date()),
      tokenGenerator: newMockTokenGenerator(),
    };
    attachOAuth2Routes(app, services as any, codeStore);
  });

  const useFederationConfig = (config: Partial<FederationConfig>) => {
    services.config = {
      FederationConfig: { Mode: "mock", Providers: {}, ...config },
    };
  };

  async function startFlow(
    options: { provider?: string; dev?: string; cookie?: string } = {},
  ): Promise<{
    stateId: string;
    page: string;
    pagePath: string;
  }> {
    const provider = options.provider ?? "Google";
    const authorize = await request(app).get("/oauth2/authorize").query({
      identity_provider: provider,
      redirect_uri: CALLBACK,
      response_type: "CODE",
      client_id: "idp-client",
      scope: "openid email profile phone",
      state: "app-state",
    });
    expect(authorize.status).toBe(302);
    const location = new URL(authorize.header.location, "http://emulator");
    expect(location.pathname).toBe(`/mock-idp/${provider}/authorize`);
    if (provider === "Google") {
      expect(location.searchParams.get("client_id")).toBe("g-client");
    }
    expect(location.searchParams.get("redirect_uri")).toMatch(
      /\/oauth2\/idpresponse$/,
    );
    const stateId = location.searchParams.get("state") ?? "";
    if (options.dev) location.searchParams.set("dev", options.dev);
    const pagePath = location.pathname + location.search;
    const pageRequest = request(app).get(pagePath);
    if (options.cookie) pageRequest.set("Cookie", options.cookie);
    const page = await pageRequest;
    expect(page.status).toBe(200);
    return { stateId, page: page.text, pagePath };
  }

  const respond = (fields: Record<string, string | string[]>) =>
    request(app)
      .post("/oauth2/idpresponse")
      .type("form")
      .send(
        new URLSearchParams(
          Object.entries(fields).flatMap(([k, v]) =>
            (Array.isArray(v) ? v : [v]).map((x) => [k, x]),
          ),
        ).toString(),
      );

  it("renders the developer form at ?dev=1, escaped, posting to /oauth2/idpresponse", async () => {
    const { stateId, page } = await startFlow({ dev: "1" });
    expect(page).toContain('action="/oauth2/idpresponse"');
    expect(page).toContain(`name="state" value="${stateId}"`);
    expect(page).toContain('value="108374529016473820195"');
    expect(page).toContain("Simulate IdP error (access_denied)");
    expect(page).toContain("data-emulator-banner");
    expect(page).toContain(
      "This page plays the role of Google's login page, so no real Google account is needed",
    );
    expect(page).toContain(
      "Pick who signs in: Subject is the user's id at Google",
    );
    expect(page).toContain(
      `<code>idp-client</code> in user pool <code>us-east-1_fed</code>`,
    );
    expect(page).toContain(`Returns to</dt><dd><code>${CALLBACK}</code>`);
    expect(page).not.toContain("<script>x</script>");
    expect(page).toContain("&lt;script&gt;x&lt;/script&gt;");
    expect(page).toContain('name="claim_name"');
    expect(page).toContain("Back to the Google sign-in page");
    expect(page).toMatch(/href="\/mock-idp\/Google\/authorize\?[^"]*dev=0"/);
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
    const page = await request(app)
      .get("/mock-idp/Google/authorize")
      .query({ state: stateId });
    expect(page.status).toBe(400);
  });

  it("accepts an OIDC-style error on GET /oauth2/idpresponse", async () => {
    const { stateId } = await startFlow();
    const res = await request(app)
      .get("/oauth2/idpresponse")
      .query({ state: stateId, error: "access_denied" });
    const location = new URL(res.header.location);
    expect(location.searchParams.get("error")).toBe("access_denied");
    expect(location.searchParams.get("error_description")).toContain("Google");
  });

  describe("the provider sign-in view", () => {
    const cookieOf = (res: { header: Record<string, any> }) =>
      ((res.header["set-cookie"] as string[] | undefined) ?? [])
        .map((c) => c.split(";")[0])
        .find((c) => c.startsWith(`${REMEMBERED_ACCOUNTS_COOKIE}=`));

    const usernameOf = (res: { header: Record<string, any> }) => {
      const location = new URL(res.header.location);
      return codeStore.consume(location.searchParams.get("code") ?? "")
        ?.username;
    };

    it("is the default: a provider sign-in page with an email form and a developer link", async () => {
      const { stateId, page } = await startFlow();
      expect(page).toContain("data-emulator-banner");
      expect(page).toContain("<h1>Sign in with Google</h1>");
      expect(page).toContain("to continue to <strong");
      expect(page).toContain("example-web");
      expect(page).toContain('name="account_email"');
      expect(page).toContain('name="account_name"');
      expect(page).not.toContain('name="claim_name"');
      expect(page).not.toContain("Choose an account");
      expect(page).toContain(`name="state" value="${stateId}"`);
      expect(page).toContain(
        "Developer options: set the subject and every claim",
      );
      expect(page).toMatch(
        new RegExp(
          `href="/mock-idp/Google/authorize\\?[^"]*state=${stateId}[^"]*&amp;dev=1"`,
        ),
      );
      expect(page).toContain(`Returns to <code>${CALLBACK}</code>`);
      expect(page).not.toContain("<script>x</script>");
    });

    it("signs a new account in with claims built from the email and name", async () => {
      const { stateId } = await startFlow();
      const res = await respond({
        state: stateId,
        account_email: "Pat.Lee@example.test",
        account_name: "Pat Van Lee",
      });
      expect(res.status).toBe(302);
      const location = new URL(res.header.location);
      expect(location.origin + location.pathname).toBe(CALLBACK);
      expect(location.searchParams.get("state")).toBe("app-state");
      expect(saved[0].Username).toMatch(/^Google_1\d{20}$/);
      expect(saved[0].Attributes).toEqual(
        expect.arrayContaining([
          { Name: "email", Value: "pat.lee@example.test" },
          { Name: "name", Value: "Pat Van Lee" },
          { Name: "given_name", Value: "Pat" },
        ]),
      );
      expect(cookieOf(res)).toBeDefined();
    });

    it("derives the same subject for the same email, whatever its case", async () => {
      const first = await startFlow();
      const a = await respond({
        state: first.stateId,
        account_email: "sam@example.test",
      });
      const second = await startFlow();
      const b = await respond({
        state: second.stateId,
        account_email: "SAM@example.test",
        account_name: "Sam",
      });
      const third = await startFlow();
      const c = await respond({
        state: third.stateId,
        account_email: "alex@example.test",
      });
      const [userA, userB, userC] = [
        usernameOf(a),
        usernameOf(b),
        usernameOf(c),
      ];
      expect(userA).toMatch(/^Google_1\d{20}$/);
      expect(userB).toBe(userA);
      expect(userC).not.toBe(userA);
    });

    it("remembers the accounts this browser used, per provider, most recent first", async () => {
      const first = await startFlow();
      const one = await respond({
        state: first.stateId,
        account_email: "sam@example.test",
        account_name: "Sam Rivera",
      });
      const second = await startFlow({ cookie: cookieOf(one) });
      expect(second.page).toContain("Choose an account");
      expect(second.page).toContain("Sam Rivera");
      expect(second.page).toContain("Use another account");
      const two = await request(app)
        .post("/oauth2/idpresponse")
        .set("Cookie", cookieOf(one) ?? "")
        .type("form")
        .send(
          new URLSearchParams({
            state: second.stateId,
            account_email: "alex@example.test",
          }).toString(),
        );
      const third = await startFlow({ cookie: cookieOf(two) });
      const alex = third.page.indexOf("alex@example.test");
      const sam = third.page.indexOf("sam@example.test");
      expect(alex).toBeGreaterThan(-1);
      expect(sam).toBeGreaterThan(alex);
      expect(third.page).toContain(
        'aria-label="Sign in as Alex, alex@example.test"',
      );

      const retyped = await request(app)
        .post("/oauth2/idpresponse")
        .set("Cookie", cookieOf(two) ?? "")
        .type("form")
        .send(
          new URLSearchParams({
            state: third.stateId,
            account_email: "SAM@Example.test",
          }).toString(),
        );
      expect(retyped.status).toBe(302);
      expect(saved.at(-1)?.Attributes).toEqual(
        expect.arrayContaining([
          { Name: "email", Value: "sam@example.test" },
          { Name: "name", Value: "Sam Rivera" },
        ]),
      );

      const corp = await startFlow({ provider: "Corp", cookie: cookieOf(two) });
      expect(corp.page).not.toContain("sam@example.test");
      expect(corp.page).toContain("<h1>Sign in with Corp</h1>");
    });

    it("ignores a remembered-accounts cookie it cannot read", async () => {
      const { page } = await startFlow({
        cookie: `${REMEMBERED_ACCOUNTS_COOKIE}=not-base64-json`,
      });
      expect(page).toContain("<h1>Sign in with Google</h1>");
    });

    it("offers the configured MockAccounts and signs in with their subject and claims", async () => {
      useFederationConfig({
        MockAccounts: [{ email: "everyone@example.test" }],
        Providers: {
          Google: {
            MockAccounts: [
              {
                email: "admin@example.test",
                name: "Ada Admin",
                sub: "100000000000000000001",
                claims: { given_name: "Adaline" },
              },
            ],
          },
        },
      });
      const { stateId, page } = await startFlow();
      expect(page).toContain("Choose an account");
      expect(page).toContain("Ada Admin");
      expect(page).not.toContain("everyone@example.test");
      const res = await respond({
        state: stateId,
        account_email: "ADMIN@example.test",
        account_name: "Someone Else",
      });
      expect(usernameOf(res)).toBe("Google_100000000000000000001");
      expect(saved[0].Attributes).toEqual(
        expect.arrayContaining([
          { Name: "name", Value: "Ada Admin" },
          { Name: "given_name", Value: "Adaline" },
        ]),
      );

      const corp = await startFlow({ provider: "Corp" });
      expect(corp.page).toContain("everyone@example.test");
      const corpRes = await respond({
        state: corp.stateId,
        account_email: "everyone@example.test",
      });
      expect(usernameOf(corpRes)).toMatch(
        /^Corp_[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );
      expect(saved.at(-1)?.Attributes).toEqual(
        expect.arrayContaining([
          { Name: "email", Value: "everyone@example.test" },
        ]),
      );
    });

    it("shows the developer form directly with MockView developer, and the sign-in view at ?dev=0", async () => {
      useFederationConfig({ MockView: "developer" });
      const developer = await startFlow();
      expect(developer.page).toContain('name="claim_name"');
      const signIn = await startFlow({ dev: "0" });
      expect(signIn.page).toContain('name="account_email"');
      useFederationConfig({
        Providers: { Google: { MockView: "developer" } },
      });
      expect((await startFlow({ provider: "Corp" })).page).toContain(
        'name="account_email"',
      );
    });

    it("asks again for an invalid email and keeps the request alive", async () => {
      const { stateId } = await startFlow();
      const res = await respond({
        state: stateId,
        account_email: "not an email",
        account_name: "Pat",
      });
      expect(res.status).toBe(400);
      expect(res.text).toContain("Enter a valid email address.");
      expect(res.text).toContain('value="not an email"');
      expect(res.text).toContain('aria-invalid="true"');
      expect(userPool.saveUser).not.toHaveBeenCalled();
      const retry = await respond({
        state: stateId,
        account_email: "pat@example.test",
      });
      expect(retry.status).toBe(302);
      expect(
        new URL(retry.header.location).searchParams.get("code"),
      ).toBeTruthy();
    });

    it("cancels with access_denied", async () => {
      const { stateId, page } = await startFlow();
      expect(page).toContain('name="error" value="access_denied"');
      const res = await respond({
        state: stateId,
        error: "access_denied",
        error_description: "User cancelled the sign-in",
      });
      const location = new URL(res.header.location);
      expect(location.searchParams.get("error")).toBe("access_denied");
      expect(location.searchParams.get("state")).toBe("app-state");
      expect(cookieOf(res)).toBeUndefined();
    });

    it("does not remember an account whose sign-in a trigger refused", async () => {
      triggers.enabled.mockImplementation((name) => name === "PreSignUp");
      triggers.preSignUp.mockRejectedValue(
        new UserLambdaValidationError(
          "PreSignUp failed with error Not invited.",
        ),
      );
      const { stateId } = await startFlow();
      const res = await respond({
        state: stateId,
        account_email: "pat@example.test",
      });
      expect(new URL(res.header.location).searchParams.get("error")).toBe(
        "invalid_request",
      );
      expect(cookieOf(res)).toBeUndefined();
    });
  });
});
