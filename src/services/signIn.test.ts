import {
  beforeEach,
  describe,
  expect,
  it,
  type MockedObject,
  vi,
} from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockMessages } from "../__tests__/mockMessages";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { UUID } from "../__tests__/patterns";
import {
  deviceSecret,
  deviceSrpClient,
  srpClient,
} from "../__tests__/srpClient";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  CodeMismatchError,
  InvalidParameterError,
  NotAuthorizedError,
  ResourceNotFoundError,
} from "../errors";
import type { AppClient } from "./appClient";
import { InMemoryAuthSessions } from "./authSessions";
import { confirmIssuedDevice, issueDevice } from "./devices";
import {
  afterPassword,
  assertUserAuthAllowed,
  availableFirstFactors,
  type ChallengeAnswer,
  respondToSignInChallenge,
  type SignInServices,
  startUserAuth,
} from "./signIn";
import { InMemorySrpSessions } from "./srp";
import { generateSecret, generate as totpCode } from "./totp";
import type { User, UserPool, UserPoolService } from "./userPoolService";

const POOL_ID = "local_SignIn1";

describe("sign-in pipeline", () => {
  let clock: ClockFake;
  let services: SignInServices;
  let messages: ReturnType<typeof newMockMessages>;
  let tokenGenerator: ReturnType<typeof newMockTokenGenerator>;
  let userPool: MockedObject<UserPoolService>;
  let client: AppClient;
  let stored: User;

  const setUp = (
    pool: Partial<UserPool> = {},
    user: Partial<User> = {},
    appClient: Partial<AppClient> = {},
  ) => {
    userPool = newMockUserPoolService({ Id: POOL_ID, ...pool });
    stored = TDB.user({
      Attributes: [
        { Name: "email", Value: "user@example.test" },
        { Name: "phone_number", Value: "+15550100" },
      ],
      ...user,
    });
    userPool.saveUser.mockImplementation(async (_ctx, saved) => {
      stored = saved;
    });
    userPool.updateUser.mockImplementation(async (ctx, _user, update) => {
      const updated = update(stored);
      await userPool.saveUser(ctx, updated);
      return updated;
    });
    userPool.listUserGroupMembership.mockResolvedValue([]);
    client = TDB.appClient({
      UserPoolId: POOL_ID,
      ExplicitAuthFlows: ["ALLOW_USER_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
      ...appClient,
    });
  };

  const round = (extra: { deviceKey?: string } = {}) => ({
    userPool,
    client,
    user: stored,
    ...extra,
  });

  const answer = (
    sessionId: string | undefined,
    challengeName: string,
    responses: Record<string, string> = {},
  ): ChallengeAnswer => ({
    userPool,
    client,
    user: stored,
    sessionId,
    challengeName,
    challengeResponses: { USERNAME: stored.Username, ...responses },
    operation: "respondToAuthChallenge",
  });

  beforeEach(() => {
    clock = new ClockFake(new Date("2026-10-21T09:00:00Z"));
    messages = newMockMessages();
    tokenGenerator = newMockTokenGenerator();
    const triggers = newMockTriggers();
    triggers.enabled.mockReturnValue(false);
    services = {
      authSessions: new InMemoryAuthSessions(clock),
      clock,
      messages,
      otp: vi.fn().mockReturnValue("12345678"),
      srpSessions: new InMemorySrpSessions(clock),
      tokenGenerator,
      triggers,
    };
    setUp();
  });

  describe("assertUserAuthAllowed", () => {
    it("accepts a client with ALLOW_USER_AUTH", () => {
      expect(() => assertUserAuthAllowed(client)).not.toThrow();
    });

    it("refuses a client without ALLOW_USER_AUTH, including the default flows", () => {
      for (const ExplicitAuthFlows of [
        ["ALLOW_USER_SRP_AUTH" as const],
        undefined,
      ]) {
        expect(() =>
          assertUserAuthAllowed(TDB.appClient({ ExplicitAuthFlows })),
        ).toThrow(
          new InvalidParameterError(
            "USER_AUTH flow not enabled for this client",
          ),
        );
      }
    });
  });

  describe("availableFirstFactors", () => {
    it("offers the password factors when the pool sets no sign-in policy", () => {
      expect(availableFirstFactors(userPool, stored)).toEqual([
        "PASSWORD",
        "PASSWORD_SRP",
      ]);
    });

    it("adds the one-time password factors the pool allows and the user can receive", () => {
      setUp({
        Policies: {
          SignInPolicy: {
            AllowedFirstAuthFactors: [
              "PASSWORD",
              "EMAIL_OTP",
              "SMS_OTP",
              "WEB_AUTHN",
            ],
          },
        },
      });
      expect(availableFirstFactors(userPool, stored)).toEqual([
        "EMAIL_OTP",
        "SMS_OTP",
        "PASSWORD",
        "PASSWORD_SRP",
      ]);

      setUp(
        {
          Policies: {
            SignInPolicy: { AllowedFirstAuthFactors: ["PASSWORD", "SMS_OTP"] },
          },
        },
        { Attributes: [{ Name: "email", Value: "user@example.test" }] },
      );
      expect(availableFirstFactors(userPool, stored)).toEqual([
        "PASSWORD",
        "PASSWORD_SRP",
      ]);
    });

    it("offers only password factors to users who must pass MFA", () => {
      const policy = {
        SignInPolicy: {
          AllowedFirstAuthFactors: ["PASSWORD" as const, "EMAIL_OTP" as const],
        },
      };
      setUp({ Policies: policy, MfaConfiguration: "ON" });
      expect(availableFirstFactors(userPool, stored)).toEqual([
        "PASSWORD",
        "PASSWORD_SRP",
      ]);

      setUp(
        { Policies: policy, MfaConfiguration: "OPTIONAL" },
        { UserMFASettingList: ["SMS_MFA"] },
      );
      expect(availableFirstFactors(userPool, stored)).toEqual([
        "PASSWORD",
        "PASSWORD_SRP",
      ]);

      setUp({ Policies: policy, MfaConfiguration: "OPTIONAL" });
      expect(availableFirstFactors(userPool, stored)).toContain("EMAIL_OTP");
    });

    it("leaves the password factors out for a user without a password", () => {
      setUp(
        {
          Policies: {
            SignInPolicy: { AllowedFirstAuthFactors: ["EMAIL_OTP"] },
          },
        },
        { Password: "" },
      );
      expect(availableFirstFactors(userPool, stored)).toEqual(["EMAIL_OTP"]);
    });
  });

  describe("USER_AUTH", () => {
    const otpPool = {
      Policies: {
        SignInPolicy: {
          AllowedFirstAuthFactors: [
            "PASSWORD" as const,
            "EMAIL_OTP" as const,
            "SMS_OTP" as const,
          ],
        },
      },
    };

    it("returns SELECT_CHALLENGE with the available challenges when no challenge is preferred", async () => {
      setUp(otpPool);

      const response = await startUserAuth(TestContext, services, round(), {
        USERNAME: stored.Username,
      });

      expect(response).toEqual({
        ChallengeName: "SELECT_CHALLENGE",
        ChallengeParameters: {},
        AvailableChallenges: [
          "EMAIL_OTP",
          "SMS_OTP",
          "PASSWORD",
          "PASSWORD_SRP",
        ],
        Session: expect.stringMatching(UUID),
      });
    });

    it("falls back to SELECT_CHALLENGE when the preferred challenge is not available", async () => {
      for (const PREFERRED_CHALLENGE of ["WEB_AUTHN", "EMAIL_OTP", "OTHER"]) {
        const response = await startUserAuth(TestContext, services, round(), {
          USERNAME: stored.Username,
          PREFERRED_CHALLENGE,
        });
        expect(response.ChallengeName).toEqual("SELECT_CHALLENGE");
        expect(response.AvailableChallenges).toEqual([
          "PASSWORD",
          "PASSWORD_SRP",
        ]);
      }
    });

    it("signs in at once with a preferred PASSWORD", async () => {
      const response = await startUserAuth(TestContext, services, round(), {
        USERNAME: stored.Username,
        PREFERRED_CHALLENGE: "PASSWORD",
        PASSWORD: stored.Password,
      });

      expect(response.AuthenticationResult?.AccessToken).toEqual("access");
      expect(tokenGenerator.generate).toHaveBeenCalledWith(
        TestContext,
        stored,
        [],
        client,
        undefined,
        "Authentication",
      );
    });

    it("refuses a wrong or missing PASSWORD", async () => {
      await expect(
        startUserAuth(TestContext, services, round(), {
          USERNAME: stored.Username,
          PREFERRED_CHALLENGE: "PASSWORD",
          PASSWORD: "wrong",
        }),
      ).rejects.toEqual(
        new NotAuthorizedError("Incorrect username or password."),
      );
      await expect(
        startUserAuth(TestContext, services, round(), {
          USERNAME: stored.Username,
          PREFERRED_CHALLENGE: "PASSWORD",
        }),
      ).rejects.toEqual(
        new InvalidParameterError("Missing required parameter PASSWORD"),
      );
    });

    it("answers a preferred PASSWORD_SRP with PASSWORD_VERIFIER and completes it", async () => {
      const srp = srpClient(POOL_ID);
      const response = await startUserAuth(TestContext, services, round(), {
        USERNAME: stored.Username,
        PREFERRED_CHALLENGE: "PASSWORD_SRP",
        SRP_A: srp.srpA,
      });
      expect(response.ChallengeName).toEqual("PASSWORD_VERIFIER");

      const tokens = await respondToSignInChallenge(
        TestContext,
        services,
        answer(
          response.Session,
          "PASSWORD_VERIFIER",
          srp.respond(response.ChallengeParameters ?? {}, stored.Password),
        ),
      );
      expect(tokens.AuthenticationResult?.AccessToken).toEqual("access");
    });

    it("sends an EMAIL_OTP code, accepts it after a wrong attempt and marks the email verified", async () => {
      setUp(otpPool);
      const response = await startUserAuth(TestContext, services, round(), {
        USERNAME: stored.Username,
        PREFERRED_CHALLENGE: "EMAIL_OTP",
      });

      expect(response).toEqual({
        ChallengeName: "EMAIL_OTP",
        ChallengeParameters: {
          CODE_DELIVERY_DELIVERY_MEDIUM: "EMAIL",
          CODE_DELIVERY_DESTINATION: "user@example.test",
        },
        Session: expect.stringMatching(UUID),
      });
      expect(messages.deliver).toHaveBeenCalledWith(
        TestContext,
        "Authentication",
        client.ClientId,
        POOL_ID,
        stored,
        "12345678",
        undefined,
        {
          DeliveryMedium: "EMAIL",
          AttributeName: "email",
          Destination: "user@example.test",
        },
      );

      await expect(
        respondToSignInChallenge(
          TestContext,
          services,
          answer(response.Session, "EMAIL_OTP", { EMAIL_OTP_CODE: "00000000" }),
        ),
      ).rejects.toBeInstanceOf(CodeMismatchError);

      const tokens = await respondToSignInChallenge(
        TestContext,
        services,
        answer(response.Session, "EMAIL_OTP", { EMAIL_OTP_CODE: "12345678" }),
      );
      expect(tokens.AuthenticationResult?.AccessToken).toEqual("access");
      expect(stored.Attributes).toContainEqual({
        Name: "email_verified",
        Value: "true",
      });

      await expect(
        respondToSignInChallenge(
          TestContext,
          services,
          answer(response.Session, "EMAIL_OTP", { EMAIL_OTP_CODE: "12345678" }),
        ),
      ).rejects.toEqual(
        new NotAuthorizedError("Invalid session for the user."),
      );
    });

    it("selects SMS_OTP from SELECT_CHALLENGE and signs in with SMS_OTP_CODE", async () => {
      setUp(otpPool);
      const select = await startUserAuth(TestContext, services, round(), {
        USERNAME: stored.Username,
      });

      const challenge = await respondToSignInChallenge(
        TestContext,
        services,
        answer(select.Session, "SELECT_CHALLENGE", { ANSWER: "SMS_OTP" }),
      );
      expect(challenge).toEqual({
        ChallengeName: "SMS_OTP",
        ChallengeParameters: {
          CODE_DELIVERY_DELIVERY_MEDIUM: "SMS",
          CODE_DELIVERY_DESTINATION: "+15550100",
        },
        Session: expect.stringMatching(UUID),
      });

      const tokens = await respondToSignInChallenge(
        TestContext,
        services,
        answer(challenge.Session, "SMS_OTP", { SMS_OTP_CODE: "12345678" }),
      );
      expect(tokens.AuthenticationResult).toBeDefined();
      expect(stored.Attributes).toContainEqual({
        Name: "phone_number_verified",
        Value: "true",
      });
    });

    it("completes PASSWORD from SELECT_CHALLENGE, by ANSWER or by ChallengeName", async () => {
      for (const [challengeName, extra] of [
        ["SELECT_CHALLENGE", { ANSWER: "PASSWORD" }],
        ["PASSWORD", {}],
      ] as const) {
        const select = await startUserAuth(TestContext, services, round(), {
          USERNAME: stored.Username,
        });
        const tokens = await respondToSignInChallenge(
          TestContext,
          services,
          answer(select.Session, challengeName, {
            ...extra,
            PASSWORD: stored.Password,
          }),
        );
        expect(tokens.AuthenticationResult?.AccessToken).toEqual("access");
      }
    });

    it("answers PASSWORD_SRP from SELECT_CHALLENGE with PASSWORD_VERIFIER", async () => {
      const select = await startUserAuth(TestContext, services, round(), {
        USERNAME: stored.Username,
      });
      const srp = srpClient(POOL_ID);
      const verifier = await respondToSignInChallenge(
        TestContext,
        services,
        answer(select.Session, "PASSWORD_SRP", { SRP_A: srp.srpA }),
      );
      expect(verifier.ChallengeName).toEqual("PASSWORD_VERIFIER");
      expect(verifier.ChallengeParameters?.USER_ID_FOR_SRP).toEqual(
        stored.Username,
      );
    });

    it("refuses an ANSWER that is not in AvailableChallenges", async () => {
      const select = await startUserAuth(TestContext, services, round(), {
        USERNAME: stored.Username,
      });
      await expect(
        respondToSignInChallenge(
          TestContext,
          services,
          answer(select.Session, "SELECT_CHALLENGE", { ANSWER: "EMAIL_OTP" }),
        ),
      ).rejects.toBeInstanceOf(InvalidParameterError);
    });

    it("refuses an unknown, foreign, expired or mismatched session", async () => {
      await expect(
        respondToSignInChallenge(
          TestContext,
          services,
          answer("unknown-session-id-0000", "SELECT_CHALLENGE", {
            ANSWER: "PASSWORD",
          }),
        ),
      ).rejects.toEqual(
        new NotAuthorizedError("Invalid session for the user."),
      );

      const select = await startUserAuth(TestContext, services, round(), {
        USERNAME: stored.Username,
      });
      await expect(
        respondToSignInChallenge(TestContext, services, {
          ...answer(select.Session, "SELECT_CHALLENGE", { ANSWER: "PASSWORD" }),
          user: TDB.user(),
        }),
      ).rejects.toEqual(
        new NotAuthorizedError("Invalid session for the user."),
      );
      await expect(
        respondToSignInChallenge(
          TestContext,
          services,
          answer(select.Session, "EMAIL_OTP", { EMAIL_OTP_CODE: "1" }),
        ),
      ).rejects.toEqual(
        new InvalidParameterError("Expected ChallengeName SELECT_CHALLENGE"),
      );

      clock.advanceBy(4 * 60_000);
      await expect(
        respondToSignInChallenge(
          TestContext,
          services,
          answer(select.Session, "SELECT_CHALLENGE", {
            ANSWER: "PASSWORD",
            PASSWORD: stored.Password,
          }),
        ),
      ).rejects.toEqual(
        new NotAuthorizedError(
          "Invalid session for the user, session is expired.",
        ),
      );
    });

    it("asks for a new password first, then issues NewPasswordChallenge tokens", async () => {
      setUp({}, { UserStatus: "FORCE_CHANGE_PASSWORD" });
      const challenge = await startUserAuth(TestContext, services, round(), {
        USERNAME: stored.Username,
        PREFERRED_CHALLENGE: "PASSWORD",
        PASSWORD: stored.Password,
      });
      expect(challenge.ChallengeName).toEqual("NEW_PASSWORD_REQUIRED");

      await respondToSignInChallenge(
        TestContext,
        services,
        answer(challenge.Session, "NEW_PASSWORD_REQUIRED", {
          NEW_PASSWORD: "New-Passw0rd!",
        }),
      );
      expect(stored.UserStatus).toEqual("CONFIRMED");
      expect(tokenGenerator.generate).toHaveBeenCalledWith(
        TestContext,
        expect.objectContaining({ Password: "New-Passw0rd!" }),
        [],
        client,
        undefined,
        "NewPasswordChallenge",
      );
    });
  });

  describe("MFA_SETUP", () => {
    it("returns MFA_SETUP when the pool requires MFA and the user has none", async () => {
      setUp({ MfaConfiguration: "ON" });
      const response = await afterPassword(TestContext, services, round());
      expect(response).toEqual({
        ChallengeName: "MFA_SETUP",
        ChallengeParameters: {
          MFAS_CAN_SETUP: '["SOFTWARE_TOKEN_MFA"]',
          USER_ID_FOR_SRP: stored.Username,
        },
        Session: expect.stringMatching(UUID),
      });
    });

    it("lists SMS_MFA when the pool sends SMS and the user has no phone number", async () => {
      setUp(
        {
          MfaConfiguration: "ON",
          SmsConfiguration: {
            SnsCallerArn: "arn:aws:iam::000000000000:role/sms",
          },
          SoftwareTokenMfaConfiguration: { Enabled: true },
        },
        { Attributes: [{ Name: "email", Value: "user@example.test" }] },
      );
      const response = await afterPassword(TestContext, services, round());
      expect(response.ChallengeParameters?.MFAS_CAN_SETUP).toEqual(
        '["SMS_MFA","SOFTWARE_TOKEN_MFA"]',
      );
    });

    it("sends SMS MFA to the user's phone number when the pool sends SMS", async () => {
      setUp({
        MfaConfiguration: "ON",
        SmsConfiguration: {
          SnsCallerArn: "arn:aws:iam::000000000000:role/sms",
        },
      });
      const response = await afterPassword(TestContext, services, round());
      expect(response.ChallengeName).toEqual("SMS_MFA");
      expect(response.ChallengeParameters?.CODE_DELIVERY_DESTINATION).toEqual(
        "+15550100",
      );
    });

    it("refuses MFA_SETUP before VerifySoftwareToken verified a code", async () => {
      setUp({ MfaConfiguration: "ON" });
      const setup = await afterPassword(TestContext, services, round());
      await expect(
        respondToSignInChallenge(
          TestContext,
          services,
          answer(setup.Session, "MFA_SETUP", {
            SOFTWARE_TOKEN_MFA_CODE: "123456",
          }),
        ),
      ).rejects.toEqual(
        new NotAuthorizedError("Invalid session for the user."),
      );
      expect(tokenGenerator.generate).not.toHaveBeenCalled();
    });

    it("prompts SELECT_MFA_TYPE when the user has several factors and no preference", async () => {
      const secret = generateSecret();
      setUp(
        { MfaConfiguration: "ON" },
        {
          UserMFASettingList: ["SMS_MFA", "SOFTWARE_TOKEN_MFA"],
          SoftwareTokenMfaConfiguration: { Secret: secret, Verified: true },
        },
      );
      const select = await afterPassword(TestContext, services, round());
      expect(select.ChallengeParameters?.MFAS_CAN_CHOOSE).toEqual(
        '["SMS_MFA","SOFTWARE_TOKEN_MFA"]',
      );

      const totp = await respondToSignInChallenge(
        TestContext,
        services,
        answer(select.Session, "SELECT_MFA_TYPE", {
          ANSWER: "SOFTWARE_TOKEN_MFA",
        }),
      );
      expect(totp.ChallengeName).toEqual("SOFTWARE_TOKEN_MFA");

      const tokens = await respondToSignInChallenge(
        TestContext,
        services,
        answer(totp.Session, "SOFTWARE_TOKEN_MFA", {
          SOFTWARE_TOKEN_MFA_CODE: totpCode(secret),
        }),
      );
      expect(tokens.AuthenticationResult).toBeDefined();
    });
  });

  describe("devices", () => {
    const tracking = {
      DeviceConfiguration: {
        ChallengeRequiredOnNewDevice: true,
        DeviceOnlyRememberedOnUserPrompt: false,
      },
    };

    const rememberDevice = (remember = true) => {
      const issued = issueDevice(POOL_ID, stored, clock.get());
      const secret = deviceSecret(
        issued.metadata.DeviceGroupKey,
        issued.metadata.DeviceKey,
      );
      stored = confirmIssuedDevice(issued.user, {
        deviceKey: issued.metadata.DeviceKey,
        verifier: secret.verifierConfig,
        rememberOnConfirm: remember,
        now: clock.get(),
      });
      return { ...issued.metadata, ...secret };
    };

    it("returns NewDeviceMetadata when the pool tracks devices and no DEVICE_KEY was sent", async () => {
      setUp(tracking);
      const response = await afterPassword(TestContext, services, round());

      expect(response.AuthenticationResult?.NewDeviceMetadata).toEqual({
        DeviceKey: expect.stringMatching(
          /^local_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
        ),
        DeviceGroupKey: expect.stringMatching(/^-/),
      });
      expect(stored.Devices).toEqual([
        expect.objectContaining({
          DeviceKey:
            response.AuthenticationResult?.NewDeviceMetadata?.DeviceKey,
          Confirmed: false,
        }),
      ]);
    });

    it("returns no NewDeviceMetadata when the pool does not track devices", async () => {
      setUp({ DeviceConfiguration: {} });
      const response = await afterPassword(TestContext, services, round());
      expect(response.AuthenticationResult?.NewDeviceMetadata).toBeUndefined();
    });

    it("refuses a DEVICE_KEY the user does not have", async () => {
      setUp(tracking);
      await expect(
        afterPassword(
          TestContext,
          services,
          round({ deviceKey: "local_00000000-0000-0000-0000-000000000000" }),
        ),
      ).rejects.toEqual(new ResourceNotFoundError("Device does not exist."));
    });

    it("replaces MFA with device SRP on a remembered device", async () => {
      const secret = generateSecret();
      setUp(
        { ...tracking, MfaConfiguration: "ON" },
        {
          UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
          SoftwareTokenMfaConfiguration: { Secret: secret, Verified: true },
        },
      );
      const device = rememberDevice();

      const deviceChallenge = await afterPassword(
        TestContext,
        services,
        round({ deviceKey: device.DeviceKey }),
      );
      expect(deviceChallenge).toEqual({
        ChallengeName: "DEVICE_SRP_AUTH",
        ChallengeParameters: {},
        Session: expect.stringMatching(UUID),
      });

      const deviceClient = deviceSrpClient(
        stored.Username,
        device.DeviceGroupKey,
        device.DeviceKey,
        device.devicePassword,
      );
      const verifier = await respondToSignInChallenge(
        TestContext,
        services,
        answer(deviceChallenge.Session, "DEVICE_SRP_AUTH", {
          DEVICE_KEY: device.DeviceKey,
          SRP_A: deviceClient.srpA,
        }),
      );
      expect(verifier).toEqual({
        ChallengeName: "DEVICE_PASSWORD_VERIFIER",
        ChallengeParameters: {
          SALT: expect.any(String),
          SRP_B: expect.any(String),
          SECRET_BLOCK: expect.any(String),
          USERNAME: stored.Username,
        },
        Session: expect.stringMatching(UUID),
      });

      clock.advanceBy(1000);
      const tokens = await respondToSignInChallenge(
        TestContext,
        services,
        answer(
          verifier.Session,
          "DEVICE_PASSWORD_VERIFIER",
          deviceClient.respond(verifier.ChallengeParameters ?? {}),
        ),
      );
      expect(tokens.AuthenticationResult?.AccessToken).toEqual("access");
      expect(tokens.AuthenticationResult?.NewDeviceMetadata).toBeUndefined();
      expect(tokenGenerator.generate).toHaveBeenCalledWith(
        TestContext,
        expect.anything(),
        [],
        client,
        undefined,
        "AuthenticateDevice",
      );
      expect(stored.Devices?.[0].DeviceLastAuthenticatedDate).toEqual(
        clock.get(),
      );
    });

    it("refuses a device claim made with the wrong device secret", async () => {
      setUp(tracking);
      const device = rememberDevice();
      const deviceChallenge = await afterPassword(
        TestContext,
        services,
        round({ deviceKey: device.DeviceKey }),
      );
      const impostor = deviceSrpClient(
        stored.Username,
        device.DeviceGroupKey,
        device.DeviceKey,
        "not the device secret",
      );
      const verifier = await respondToSignInChallenge(
        TestContext,
        services,
        answer(deviceChallenge.Session, "DEVICE_SRP_AUTH", {
          SRP_A: impostor.srpA,
        }),
      );
      await expect(
        respondToSignInChallenge(
          TestContext,
          services,
          answer(
            verifier.Session,
            "DEVICE_PASSWORD_VERIFIER",
            impostor.respond(verifier.ChallengeParameters ?? {}),
          ),
        ),
      ).rejects.toEqual(
        new NotAuthorizedError("Incorrect username or password."),
      );
    });

    it("keeps MFA on a device that is confirmed but not remembered", async () => {
      setUp(
        { ...tracking, MfaConfiguration: "ON" },
        {
          UserMFASettingList: ["SMS_MFA"],
        },
      );
      const device = rememberDevice(false);
      const response = await afterPassword(
        TestContext,
        services,
        round({ deviceKey: device.DeviceKey }),
      );
      expect(response.ChallengeName).toEqual("SMS_MFA");

      const tokens = await respondToSignInChallenge(
        TestContext,
        services,
        answer(response.Session, "SMS_MFA", { SMS_MFA_CODE: "12345678" }),
      );
      expect(tokens.AuthenticationResult?.NewDeviceMetadata).toBeUndefined();
    });

    it("keeps MFA on a remembered device when ChallengeRequiredOnNewDevice is false", async () => {
      setUp(
        {
          DeviceConfiguration: { ChallengeRequiredOnNewDevice: false },
          MfaConfiguration: "ON",
        },
        { UserMFASettingList: ["SMS_MFA"] },
      );
      const device = rememberDevice();
      const response = await afterPassword(
        TestContext,
        services,
        round({ deviceKey: device.DeviceKey }),
      );
      expect(response.ChallengeName).toEqual("SMS_MFA");
    });
  });
});
