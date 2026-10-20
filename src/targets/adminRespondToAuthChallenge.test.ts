import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  CodeMismatchError,
  InvalidParameterError,
  InvalidPasswordError,
  NotAuthorizedError,
} from "../errors";
import {
  InMemoryAuthSessions,
  type Triggers,
  type UserPoolService,
} from "../services";
import type { TokenGenerator } from "../services/tokenGenerator";
import { generateSecret, generate as genTotp } from "../services/totp";
import {
  AdminRespondToAuthChallenge,
  type AdminRespondToAuthChallengeTarget,
} from "./adminRespondToAuthChallenge";

const currentDate = new Date();

describe("AdminRespondToAuthChallenge target", () => {
  let adminRespondToAuthChallenge: AdminRespondToAuthChallengeTarget;
  let mockTokenGenerator: MockedObject<TokenGenerator>;
  let mockTriggers: MockedObject<Triggers>;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let clock: ClockFake;
  let authSessions: InMemoryAuthSessions;
  const userPoolClient = TDB.appClient();

  beforeEach(() => {
    clock = new ClockFake(currentDate);
    mockTokenGenerator = newMockTokenGenerator();
    mockTriggers = newMockTriggers();
    mockUserPoolService = newMockUserPoolService({
      Id: userPoolClient.UserPoolId,
    });

    const mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockCognitoService.getAppClient.mockResolvedValue(userPoolClient);

    authSessions = new InMemoryAuthSessions(clock);
    adminRespondToAuthChallenge = AdminRespondToAuthChallenge({
      authSessions,
      clock,
      cognito: mockCognitoService,
      tokenGenerator: mockTokenGenerator,
      triggers: mockTriggers,
    });
  });

  it("throws if user doesn't exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      adminRespondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        ChallengeName: "SMS_MFA",
        ChallengeResponses: {
          USERNAME: "username",
          SMS_MFA_CODE: "123456",
        },
        Session: "Session",
      }),
    ).rejects.toBeInstanceOf(NotAuthorizedError);
  });

  it("throws if ChallengeResponses missing", async () => {
    await expect(
      adminRespondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        ChallengeName: "SMS_MFA",
      }),
    ).rejects.toEqual(
      new InvalidParameterError(
        "Missing required parameter challenge responses",
      ),
    );
  });

  describe("ChallengeName=SMS_MFA", () => {
    const user = TDB.user({ MFACode: "123456" });

    beforeEach(() => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    });

    it("updates the user and removes MFACode when code matches", async () => {
      const newDate = clock.advanceBy(1200);

      await adminRespondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        ChallengeName: "SMS_MFA",
        ChallengeResponses: {
          USERNAME: user.Username,
          SMS_MFA_CODE: "123456",
        },
        Session: "Session",
      });

      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
        ...user,
        MFACode: undefined,
        UserLastModifiedDate: newDate,
      });
    });

    it("generates tokens", async () => {
      mockTokenGenerator.generate.mockResolvedValue({
        AccessToken: "access",
        IdToken: "id",
        RefreshToken: "refresh",
      });
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

      const output = await adminRespondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        ChallengeName: "SMS_MFA",
        ChallengeResponses: {
          USERNAME: user.Username,
          SMS_MFA_CODE: "123456",
        },
        Session: "Session",
      });

      expect(output.AuthenticationResult?.AccessToken).toEqual("access");
      expect(output.AuthenticationResult?.IdToken).toEqual("id");
      expect(output.AuthenticationResult?.RefreshToken).toEqual("refresh");
    });

    it("throws when code is incorrect", async () => {
      await expect(
        adminRespondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          UserPoolId: userPoolClient.UserPoolId,
          ChallengeName: "SMS_MFA",
          ChallengeResponses: {
            USERNAME: user.Username,
            SMS_MFA_CODE: "wrong",
          },
          Session: "Session",
        }),
      ).rejects.toBeInstanceOf(CodeMismatchError);
    });
  });

  describe("ChallengeName=SOFTWARE_TOKEN_MFA", () => {
    const secret = generateSecret();
    const user = TDB.user({
      SoftwareTokenMfaConfiguration: { Secret: secret, Verified: true },
    });

    beforeEach(() => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    });

    it("generates tokens when code matches", async () => {
      mockTokenGenerator.generate.mockResolvedValue({
        AccessToken: "access",
        IdToken: "id",
        RefreshToken: "refresh",
      });
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

      const output = await adminRespondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        ChallengeName: "SOFTWARE_TOKEN_MFA",
        ChallengeResponses: {
          USERNAME: user.Username,
          SOFTWARE_TOKEN_MFA_CODE: genTotp(secret),
        },
        Session: "Session",
      });

      expect(output.AuthenticationResult?.AccessToken).toEqual("access");
    });

    it("throws when code is incorrect", async () => {
      await expect(
        adminRespondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          UserPoolId: userPoolClient.UserPoolId,
          ChallengeName: "SOFTWARE_TOKEN_MFA",
          ChallengeResponses: {
            USERNAME: user.Username,
            SOFTWARE_TOKEN_MFA_CODE: "000000",
          },
          Session: "Session",
        }),
      ).rejects.toBeInstanceOf(CodeMismatchError);
    });
  });

  describe("ChallengeName=NEW_PASSWORD_REQUIRED", () => {
    const user = TDB.user();

    beforeEach(() => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    });

    it("rejects a new password that breaks the password policy", async () => {
      await expect(
        adminRespondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          UserPoolId: userPoolClient.UserPoolId,
          ChallengeName: "NEW_PASSWORD_REQUIRED",
          ChallengeResponses: {
            USERNAME: user.Username,
            NEW_PASSWORD: "newpass",
          },
          Session: "Session",
        }),
      ).rejects.toEqual(
        new InvalidPasswordError(
          "Password does not conform to policy: Password not long enough",
        ),
      );
      expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
    });

    it("updates the user's password and status", async () => {
      const newDate = clock.advanceBy(1200);

      await adminRespondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        ChallengeName: "NEW_PASSWORD_REQUIRED",
        ChallengeResponses: {
          USERNAME: user.Username,
          NEW_PASSWORD: "newpass-Aa1",
        },
        Session: "Session",
      });

      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
        ...user,
        Password: "newpass-Aa1",
        UserLastModifiedDate: newDate,
        UserStatus: "CONFIRMED",
      });
    });

    it("generates tokens", async () => {
      mockTokenGenerator.generate.mockResolvedValue({
        AccessToken: "access",
        IdToken: "id",
        RefreshToken: "refresh",
      });
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

      const output = await adminRespondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        ChallengeName: "NEW_PASSWORD_REQUIRED",
        ChallengeResponses: {
          USERNAME: user.Username,
          NEW_PASSWORD: "newpass-Aa1",
        },
        Session: "Session",
      });

      expect(output.AuthenticationResult?.AccessToken).toEqual("access");
    });
  });
  describe("CUSTOM_CHALLENGE challenge", () => {
    it("retries after a wrong answer and issues tokens on the correct one", async () => {
      const user = TDB.user();
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
      mockTokenGenerator.generate.mockResolvedValue({
        AccessToken: "access",
        IdToken: "id",
        RefreshToken: "refresh",
      });
      mockTriggers.enabled.mockImplementation(
        (name) => name !== "PostAuthentication",
      );
      mockTriggers.defineAuthChallenge.mockImplementation(
        async (_ctx, { session }) => ({
          challengeName: "CUSTOM_CHALLENGE",
          issueTokens: session.at(-1)?.challengeResult === true,
          failAuthentication: false,
        }),
      );
      mockTriggers.createAuthChallenge.mockResolvedValue({
        publicChallengeParameters: {},
        privateChallengeParameters: { secretLoginCode: "123456" },
        challengeMetadata: "CODE-123456",
      });
      mockTriggers.verifyAuthChallengeResponse.mockImplementation(
        async (_ctx, { challengeAnswer, privateChallengeParameters }) => ({
          answerCorrect:
            challengeAnswer === privateChallengeParameters?.secretLoginCode,
        }),
      );
      const session = authSessions.create({
        userPoolId: userPoolClient.UserPoolId,
        clientId: userPoolClient.ClientId,
        username: user.Username,
        history: [],
        pendingChallenge: {
          challengeName: "CUSTOM_CHALLENGE",
          privateChallengeParameters: { secretLoginCode: "123456" },
          challengeMetadata: "CODE-123456",
        },
      });
      const respond = (Session: string, ANSWER: string) =>
        adminRespondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          UserPoolId: userPoolClient.UserPoolId,
          ChallengeName: "CUSTOM_CHALLENGE",
          ChallengeResponses: { USERNAME: user.Username, ANSWER },
          Session,
        });

      const first = await respond(session, "000000");
      expect(first.ChallengeName).toEqual("CUSTOM_CHALLENGE");

      const second = await respond(first.Session as string, "123456");
      expect(second.AuthenticationResult?.IdToken).toEqual("id");
    });
  });
});
