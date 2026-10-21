import bodyParser from "body-parser";
import express from "express";
import supertest from "supertest";
import type { MockedObject } from "vitest";
import { beforeEach, describe, expect, it } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockMessages } from "../__tests__/mockMessages";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTokenVerifier } from "../__tests__/mockTokenVerifier";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import * as TDB from "../__tests__/testDataBuilder";
import { NotAuthorizedError, UserLambdaValidationError } from "../errors";
import type { Messages, Triggers, UserPoolService } from "../services";
import { generate as generateTotp } from "../services/totp";
import type { User } from "../services/userPoolService";
import { AuthorizationCodeStore } from "./authorizationCodeStore";
import { HostedLoginStore } from "./hostedLoginStore";
import { attachOAuth2Routes } from "./routes";

const CALLBACK = "http://localhost:9876/cb";
const PASSWORD = "Passw0rd!";
const NEW_PASSWORD = "NewPassw0rd!";
const TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

const loginForm = {
  client_id: "client-1",
  redirect_uri: CALLBACK,
  response_type: "code",
  scope: "openid email",
  state: "st-1",
  username: "user@example.test",
  password: PASSWORD,
};

const sessionOf = (html: string): string => {
  const match = html.match(/name="login_session" value="([^"]+)"/);
  if (!match) throw new Error(`no login_session in ${html}`);
  return match[1];
};

describe("hosted login form", () => {
  let clock: ClockFake;
  let userPool: MockedObject<UserPoolService>;
  let triggers: MockedObject<Triggers>;
  let messages: MockedObject<Messages>;
  let codeStore: AuthorizationCodeStore;
  let stored: User;
  let config: Record<string, unknown>;
  let tokenGenerator: ReturnType<typeof newMockTokenGenerator>;
  let app: express.Express;

  const setUser = (partial: Partial<User>) => {
    stored = TDB.user({
      Username: "user@example.test",
      Password: PASSWORD,
      UserStatus: "CONFIRMED",
      Attributes: [
        { Name: "sub", Value: "00000000-0000-4000-8000-0000000000aa" },
        { Name: "email", Value: "user@example.test" },
        { Name: "phone_number", Value: "+15555550100" },
      ],
      ...partial,
    });
  };

  const login = (overrides: Record<string, string> = {}) =>
    supertest(app)
      .post("/oauth2/authorize")
      .type("form")
      .send({ ...loginForm, ...overrides });

  const submitStep = (fields: Record<string, string>) =>
    supertest(app).post("/oauth2/authorize").type("form").send(fields);

  const expectCodeRedirect = (res: supertest.Response) => {
    expect(res.status).toBe(302);
    const location = new URL(res.header.location);
    expect(`${location.origin}${location.pathname}`).toBe(CALLBACK);
    expect(location.searchParams.get("state")).toBe("st-1");
    const code = location.searchParams.get("code") as string;
    expect(codeStore.consume(code)).toMatchObject({
      clientId: "client-1",
      username: "user@example.test",
      redirectUri: CALLBACK,
      scope: "openid email",
    });
  };

  beforeEach(() => {
    clock = new ClockFake(new Date("2026-01-01T00:00:00Z"));
    setUser({});
    config = {};

    userPool = newMockUserPoolService({ Id: "local_Pool1" });
    userPool.getUserByUsername.mockImplementation(async (_ctx, username) =>
      username === stored.Username ? stored : null,
    );
    userPool.saveUser.mockImplementation(async (_ctx, user) => {
      stored = user;
    });
    userPool.listUserGroupMembership.mockResolvedValue([]);

    const cognito = newMockCognitoService(userPool);
    cognito.getAppClient.mockResolvedValue(
      TDB.appClient({
        ClientId: "client-1",
        UserPoolId: "local_Pool1",
        CallbackURLs: [CALLBACK],
        AllowedOAuthFlows: ["code", "implicit"],
        AllowedOAuthScopes: ["openid", "email"],
      }),
    );
    cognito.getUserPoolForClientId.mockResolvedValue(userPool);
    cognito.getUserPool.mockResolvedValue(userPool);

    triggers = newMockTriggers();
    triggers.enabled.mockReturnValue(false);
    messages = newMockMessages();
    tokenGenerator = newMockTokenGenerator();
    tokenGenerator.generate.mockResolvedValue({
      AccessToken: "access-token",
      IdToken: "id-token",
      RefreshToken: "refresh-token",
      ExpiresIn: 3600,
      TokenType: "Bearer",
    });
    codeStore = new AuthorizationCodeStore();

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
    attachOAuth2Routes(
      app,
      {
        clock,
        cognito,
        config,
        messages,
        otp: () => "246810",
        tokenGenerator,
        tokenVerifier: newMockTokenVerifier(),
        triggers,
      } as any,
      codeStore,
      undefined,
      new HostedLoginStore(clock),
    );
  });

  it("signs a confirmed user straight in", async () => {
    expectCodeRedirect(await login());
  });

  describe("disabled user", () => {
    it("shows User is disabled. and issues no code", async () => {
      setUser({ Enabled: false });
      const res = await login();
      expect(res.status).toBe(200);
      expect(res.text).toContain("User is disabled.");
      expect(res.text).toContain('name="username"');
      expect(res.header.location).toBeUndefined();
      expect(tokenGenerator.generate).not.toHaveBeenCalled();
    });

    it("reports a wrong password as incorrect credentials", async () => {
      setUser({ Enabled: false });
      const res = await login({ password: "wrong" });
      expect(res.text).toContain("Incorrect username or password.");
      expect(res.text).not.toContain("User is disabled.");
    });
  });

  it("refuses RESET_REQUIRED with the password reset notice", async () => {
    setUser({ UserStatus: "RESET_REQUIRED" });
    const res = await login();
    expect(res.status).toBe(200);
    expect(res.text).toContain("Password reset required for the user.");
    expect(res.header.location).toBeUndefined();
  });

  it("keeps refusing an unconfirmed user as incorrect credentials", async () => {
    setUser({ UserStatus: "UNCONFIRMED" });
    const res = await login();
    expect(res.text).toContain("Incorrect username or password.");
  });

  describe("FORCE_CHANGE_PASSWORD", () => {
    beforeEach(() => setUser({ UserStatus: "FORCE_CHANGE_PASSWORD" }));

    it("rejects a wrong temporary password", async () => {
      const res = await login({ password: "wrong" });
      expect(res.text).toContain("Incorrect username or password.");
      expect(res.text).not.toContain("login_session");
    });

    it("shows the new password step without the username in the form", async () => {
      const res = await login();
      expect(res.status).toBe(200);
      expect(res.text).toContain('name="new_password"');
      expect(res.text).not.toContain("user@example.test");
      expect(res.text).not.toContain(PASSWORD);
      expect(sessionOf(res.text)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    });

    it("enforces the pool password policy and keeps the step", async () => {
      const session = sessionOf((await login()).text);
      const weak = await submitStep({
        login_session: session,
        new_password: "short",
        confirm_password: "short",
      });
      expect(weak.status).toBe(200);
      expect(weak.text).toContain(
        "Password does not conform to policy: Password not long enough",
      );
      expect(sessionOf(weak.text)).toBe(session);
      expect(stored.UserStatus).toBe("FORCE_CHANGE_PASSWORD");

      expectCodeRedirect(
        await submitStep({
          login_session: session,
          new_password: NEW_PASSWORD,
          confirm_password: NEW_PASSWORD,
        }),
      );
      expect(stored.UserStatus).toBe("CONFIRMED");
      expect(stored.Password).toBe(NEW_PASSWORD);
    });

    it("skips the policy when PasswordPolicyConfig.Enforce is false", async () => {
      config.PasswordPolicyConfig = { Enforce: false };
      const session = sessionOf((await login()).text);
      expectCodeRedirect(
        await submitStep({ login_session: session, new_password: "short" }),
      );
      expect(stored.Password).toBe("short");
    });

    it("rejects a confirmation that does not match", async () => {
      const session = sessionOf((await login()).text);
      const res = await submitStep({
        login_session: session,
        new_password: NEW_PASSWORD,
        confirm_password: "Different1!",
      });
      expect(res.text).toContain("Passwords do not match.");
      expect(stored.UserStatus).toBe("FORCE_CHANGE_PASSWORD");
    });

    it("asks for MFA after the new password when MFA is required", async () => {
      userPool.options.MfaConfiguration = "ON";
      setUser({
        UserStatus: "FORCE_CHANGE_PASSWORD",
        UserMFASettingList: ["SMS_MFA"],
      });
      const session = sessionOf((await login()).text);
      const res = await submitStep({
        login_session: session,
        new_password: NEW_PASSWORD,
      });
      expect(res.status).toBe(200);
      expect(res.text).toContain('name="code"');
      expect(stored.UserStatus).toBe("CONFIRMED");
      expect(messages.deliver).toHaveBeenCalledTimes(1);
    });
  });

  describe("SMS MFA", () => {
    beforeEach(() => {
      userPool.options.MfaConfiguration = "OPTIONAL";
      setUser({ UserMFASettingList: ["SMS_MFA"] });
    });

    it("delivers a code through message delivery and accepts it", async () => {
      const res = await login();
      expect(res.status).toBe(200);
      expect(res.text).toContain("+*******0100");
      expect(messages.deliver).toHaveBeenCalledWith(
        expect.anything(),
        "Authentication",
        "client-1",
        "local_Pool1",
        expect.objectContaining({ Username: "user@example.test" }),
        "246810",
        undefined,
        {
          DeliveryMedium: "SMS",
          AttributeName: "phone_number",
          Destination: "+15555550100",
        },
      );

      const session = sessionOf(res.text);
      const wrong = await submitStep({
        login_session: session,
        code: "000000",
      });
      expect(wrong.status).toBe(200);
      expect(wrong.text).toContain("Invalid code or auth state for the user.");
      expect(sessionOf(wrong.text)).toBe(session);

      expectCodeRedirect(
        await submitStep({ login_session: session, code: "246810" }),
      );
    });

    it("is used up once sign-in completes", async () => {
      const session = sessionOf((await login()).text);
      await submitStep({ login_session: session, code: "246810" });
      const replay = await submitStep({
        login_session: session,
        code: "246810",
      });
      expect(replay.status).toBe(400);
      expect(replay.text).toContain(
        "Invalid session for the user, session is expired.",
      );
    });

    it("expires the pending step after the auth session validity", async () => {
      const session = sessionOf((await login()).text);
      clock.advanceBy(3 * 60_000);
      const res = await submitStep({ login_session: session, code: "246810" });
      expect(res.status).toBe(400);
      expect(res.text).toContain("session is expired");
      expect(res.header.location).toBeUndefined();
    });

    it("ignores a username sent with a step", async () => {
      const session = sessionOf((await login()).text);
      userPool.getUserByUsername.mockClear();
      expectCodeRedirect(
        await submitStep({
          login_session: session,
          code: "246810",
          username: "someone-else@example.test",
          client_id: "other-client",
          redirect_uri: "http://attacker.example.test/cb",
        }),
      );
      expect(userPool.getUserByUsername).toHaveBeenCalledWith(
        expect.anything(),
        "user@example.test",
      );
    });

    it("rejects an unknown session id", async () => {
      const res = await submitStep({ login_session: "nope", code: "246810" });
      expect(res.status).toBe(400);
    });

    it("refuses a user disabled between the steps", async () => {
      const session = sessionOf((await login()).text);
      stored = { ...stored, Enabled: false };
      const res = await submitStep({ login_session: session, code: "246810" });
      expect(res.text).toContain("User is disabled.");
      expect(res.header.location).toBeUndefined();
    });

    it("explains when the user has no phone number", async () => {
      setUser({ UserMFASettingList: ["SMS_MFA"], Attributes: [] });
      const res = await login();
      expect(res.text).toContain("no phone number");
      expect(messages.deliver).not.toHaveBeenCalled();
    });
  });

  describe("TOTP MFA", () => {
    beforeEach(() => {
      userPool.options.MfaConfiguration = "ON";
      setUser({
        UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
        SoftwareTokenMfaConfiguration: { Secret: TOTP_SECRET, Verified: true },
      });
    });

    it("verifies the code against the user's software token", async () => {
      const res = await login();
      expect(res.text).toContain("authenticator app");
      const session = sessionOf(res.text);

      const wrong = await submitStep({ login_session: session, code: "12" });
      expect(wrong.text).toContain("Invalid code or auth state for the user.");

      expectCodeRedirect(
        await submitStep({
          login_session: session,
          code: generateTotp(TOTP_SECRET),
        }),
      );
      expect(messages.deliver).not.toHaveBeenCalled();
    });
  });

  describe("several MFA methods", () => {
    beforeEach(() => {
      userPool.options.MfaConfiguration = "OPTIONAL";
      setUser({
        UserMFASettingList: ["SMS_MFA", "SOFTWARE_TOKEN_MFA"],
        SoftwareTokenMfaConfiguration: { Secret: TOTP_SECRET, Verified: true },
      });
    });

    it("lets the user choose when none is preferred", async () => {
      const res = await login();
      expect(res.text).toContain('value="SMS_MFA"');
      expect(res.text).toContain('value="SOFTWARE_TOKEN_MFA"');
      const chosen = await submitStep({
        login_session: sessionOf(res.text),
        mfa_method: "SOFTWARE_TOKEN_MFA",
      });
      expect(chosen.text).toContain("authenticator app");
      expectCodeRedirect(
        await submitStep({
          login_session: sessionOf(chosen.text),
          code: generateTotp(TOTP_SECRET),
        }),
      );
    });

    it("goes straight to the preferred method", async () => {
      stored = { ...stored, PreferredMfaSetting: "SMS_MFA" };
      const res = await login();
      expect(res.text).toContain('name="code"');
      expect(messages.deliver).toHaveBeenCalledTimes(1);
    });
  });

  it("refuses when MFA is on but the user has no method set up", async () => {
    userPool.options.MfaConfiguration = "ON";
    const res = await login();
    expect(res.text).toContain("must set up MFA");
    expect(res.header.location).toBeUndefined();
  });

  describe("PostAuthentication", () => {
    beforeEach(() => {
      triggers.enabled.mockImplementation(
        (name) => name === "PostAuthentication",
      );
      triggers.postAuthentication.mockImplementation(async () => {
        stored = {
          ...stored,
          Attributes: [
            ...stored.Attributes,
            { Name: "email_verified", Value: "true" },
          ],
        };
      });
    });

    it("runs after a password sign-in", async () => {
      expectCodeRedirect(await login());
      expect(triggers.postAuthentication).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          clientId: "client-1",
          clientMetadata: undefined,
          source: "PostAuthentication_Authentication",
          username: "user@example.test",
          userPoolId: "local_Pool1",
        }),
      );
    });

    it("issues implicit tokens from the user as the trigger left it", async () => {
      const res = await login({ response_type: "token" });
      expect(res.status).toBe(302);
      const [, tokenUser] = tokenGenerator.generate.mock.calls[0];
      expect(tokenUser.Attributes).toContainEqual({
        Name: "email_verified",
        Value: "true",
      });
    });

    it("runs only after the MFA step succeeds", async () => {
      userPool.options.MfaConfiguration = "OPTIONAL";
      setUser({ UserMFASettingList: ["SMS_MFA"] });
      const session = sessionOf((await login()).text);
      expect(triggers.postAuthentication).not.toHaveBeenCalled();
      await submitStep({ login_session: session, code: "000000" });
      expect(triggers.postAuthentication).not.toHaveBeenCalled();
      await submitStep({ login_session: session, code: "246810" });
      expect(triggers.postAuthentication).toHaveBeenCalledTimes(1);
    });
  });

  describe("PreAuthentication", () => {
    beforeEach(() => {
      triggers.enabled.mockImplementation(
        (name) => name === "PreAuthentication",
      );
    });

    it("runs before the password is checked", async () => {
      expectCodeRedirect(await login());
      expect(triggers.preAuthentication).toHaveBeenCalledWith(
        expect.anything(),
        {
          clientId: "client-1",
          source: "PreAuthentication_Authentication",
          userAttributes: stored.Attributes,
          userNotFound: undefined,
          username: "user@example.test",
          userPoolId: "local_Pool1",
          validationData: undefined,
        },
      );
    });

    it("shows the trigger's error and issues nothing when it throws", async () => {
      triggers.preAuthentication.mockRejectedValue(
        new UserLambdaValidationError(
          "PreAuthentication failed with error blocked.",
        ),
      );
      const res = await login({ password: "wrong" });
      expect(res.text).toContain(
        "PreAuthentication failed with error blocked.",
      );
      expect(res.header.location).toBeUndefined();
      expect(tokenGenerator.generate).not.toHaveBeenCalled();
    });

    it("does not run for an unknown user", async () => {
      const res = await login({ username: "unknown@example.test" });
      expect(res.text).toContain("Incorrect username or password.");
      expect(triggers.preAuthentication).not.toHaveBeenCalled();
    });
  });

  describe("UserMigration", () => {
    beforeEach(() => {
      triggers.enabled.mockImplementation((name) => name === "UserMigration");
    });

    it("signs in a user the trigger migrates", async () => {
      const migrated = TDB.user({
        Username: "migrated@example.test",
        Password: PASSWORD,
        UserStatus: "CONFIRMED",
      });
      triggers.userMigration.mockResolvedValue(migrated);
      const res = await login({ username: "migrated@example.test" });
      expect(triggers.userMigration).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          clientId: "client-1",
          username: "migrated@example.test",
          password: PASSWORD,
          userPoolId: "local_Pool1",
        }),
      );
      expect(res.status).toBe(302);
      const code = new URL(res.header.location).searchParams.get("code");
      expect(codeStore.consume(code as string)?.username).toBe(
        "migrated@example.test",
      );
    });

    it("shows incorrect credentials when the trigger refuses", async () => {
      triggers.userMigration.mockRejectedValue(new NotAuthorizedError());
      const res = await login({ username: "unknown@example.test" });
      expect(res.text).toContain("Incorrect username or password.");
    });
  });
});

describe("HostedLoginStore", () => {
  const pending = {
    userPoolId: "local_Pool1",
    clientId: "client-1",
    username: "user@example.test",
    redirectUri: CALLBACK,
    state: undefined,
    scope: "",
    flow: {
      responseType: "code" as const,
      scopes: [],
      codeChallenge: undefined,
      codeChallengeMethod: undefined,
    },
    step: { kind: "newPassword" as const },
  };

  it("keeps a login until it expires or is deleted", () => {
    const clock = new ClockFake(new Date());
    const store = new HostedLoginStore(clock, 1000);
    const id = store.create(pending);
    expect(store.peek(id)).toEqual(pending);
    clock.advanceBy(999);
    expect(store.peek(id)).toEqual(pending);
    clock.advanceBy(1);
    expect(store.peek(id)).toBeNull();

    const other = store.create(pending);
    store.delete(other);
    expect(store.peek(other)).toBeNull();
    expect(store.peek(undefined)).toBeNull();
  });
});
