import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTokenVerifier } from "../__tests__/mockTokenVerifier";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  type CognitoService,
  DateClock,
  InMemoryAuthSessions,
  type Triggers,
  type UserPoolService,
} from "../services";
import type { TokenGenerator } from "../services/tokenGenerator";
import type { TokenVerifier } from "../services/tokenVerifier";
import {
  AdminInitiateAuth,
  type AdminInitiateAuthTarget,
} from "./adminInitiateAuth";

describe("AdminInitiateAuth target", () => {
  let adminInitiateAuth: AdminInitiateAuthTarget;

  let mockCognitoService: MockedObject<CognitoService>;
  let mockTokenGenerator: MockedObject<TokenGenerator>;
  let mockTokenVerifier: MockedObject<TokenVerifier>;
  let mockTriggers: MockedObject<Triggers>;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let authSessions: InMemoryAuthSessions;
  const userPoolClient = TDB.appClient();

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService({
      Id: userPoolClient.UserPoolId,
    });
    mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockCognitoService.getAppClient.mockResolvedValue(userPoolClient);
    mockTriggers = newMockTriggers();
    mockTokenGenerator = newMockTokenGenerator();
    mockTokenVerifier = newMockTokenVerifier();
    authSessions = new InMemoryAuthSessions(new DateClock());
    adminInitiateAuth = AdminInitiateAuth({
      authSessions,
      triggers: mockTriggers,
      cognito: mockCognitoService,
      tokenGenerator: mockTokenGenerator,
      tokenVerifier: mockTokenVerifier,
      clock: new ClockFake(new Date()),
    });
  });

  it("invokes PostAuthentication without ClientMetadata before issuing tokens", async () => {
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "access",
      IdToken: "id",
      RefreshToken: "refresh",
      ExpiresIn: 3600,
      TokenType: "Bearer",
    });
    mockTriggers.enabled.mockImplementation(
      (name) => name === "PostAuthentication",
    );
    const existingUser = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);
    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

    await adminInitiateAuth(TestContext, {
      AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
      ClientId: userPoolClient.ClientId,
      UserPoolId: userPoolClient.UserPoolId,
      AuthParameters: {
        USERNAME: existingUser.Username,
        PASSWORD: existingUser.Password,
      },
      ClientMetadata: { client: "metadata" },
    });

    expect(mockTriggers.postAuthentication).toHaveBeenCalledWith(TestContext, {
      clientId: userPoolClient.ClientId,
      clientMetadata: undefined,
      source: "PostAuthentication_Authentication",
      userAttributes: existingUser.Attributes,
      username: existingUser.Username,
      userPoolId: userPoolClient.UserPoolId,
    });
  });

  it("create tokens with username, password and admin user password auth flow", async () => {
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "access",
      IdToken: "id",
      RefreshToken: "refresh",
      ExpiresIn: 3600,
      TokenType: "Bearer",
    });

    const existingUser = TDB.user();

    mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);
    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

    const response = await adminInitiateAuth(TestContext, {
      AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
      ClientId: userPoolClient.ClientId,
      UserPoolId: userPoolClient.UserPoolId,
      AuthParameters: {
        USERNAME: existingUser.Username,
        PASSWORD: existingUser.Password,
      },
      ClientMetadata: {
        client: "metadata",
      },
    });

    expect(mockUserPoolService.storeRefreshToken).toHaveBeenCalledWith(
      TestContext,
      response.AuthenticationResult?.RefreshToken,
      existingUser,
    );

    expect(response.AuthenticationResult?.AccessToken).toEqual("access");
    expect(response.AuthenticationResult?.IdToken).toEqual("id");
    expect(response.AuthenticationResult?.RefreshToken).toEqual("refresh");

    expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
      TestContext,
      existingUser,
      [],
      userPoolClient,
      {
        client: "metadata",
      },
      "Authentication",
    );
  });

  describe("MFA enforcement", () => {
    it("returns SMS_MFA challenge when MfaConfiguration is ON and user has SMS MFA", async () => {
      const existingUser = TDB.user({
        MFAOptions: [{ DeliveryMedium: "SMS", AttributeName: "phone_number" }],
      });
      mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);
      mockUserPoolService.options.MfaConfiguration = "ON";

      const response = await adminInitiateAuth(TestContext, {
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        AuthParameters: {
          USERNAME: existingUser.Username,
          PASSWORD: existingUser.Password,
        },
      });

      expect(response.ChallengeName).toEqual("SMS_MFA");
      expect(response.ChallengeParameters).toEqual({
        USER_ID_FOR_SRP: existingUser.Username,
      });
      expect(response.AuthenticationResult).toBeUndefined();
      expect(mockTokenGenerator.generate).not.toHaveBeenCalled();
    });

    it("returns SOFTWARE_TOKEN_MFA challenge when MfaConfiguration is ON and user prefers TOTP", async () => {
      const existingUser = TDB.user({
        UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
        PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
      });
      mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);
      mockUserPoolService.options.MfaConfiguration = "ON";

      const response = await adminInitiateAuth(TestContext, {
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        AuthParameters: {
          USERNAME: existingUser.Username,
          PASSWORD: existingUser.Password,
        },
      });

      expect(response.ChallengeName).toEqual("SOFTWARE_TOKEN_MFA");
      expect(response.AuthenticationResult).toBeUndefined();
    });

    it("throws NotAuthorizedError when MfaConfiguration is ON but user has no MFA configured", async () => {
      const existingUser = TDB.user();
      mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);
      mockUserPoolService.options.MfaConfiguration = "ON";

      await expect(
        adminInitiateAuth(TestContext, {
          AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
          ClientId: userPoolClient.ClientId,
          UserPoolId: userPoolClient.UserPoolId,
          AuthParameters: {
            USERNAME: existingUser.Username,
            PASSWORD: existingUser.Password,
          },
        }),
      ).rejects.toThrow("User not authorized");
    });

    it("returns MFA challenge when MfaConfiguration is OPTIONAL and user has MFA", async () => {
      const existingUser = TDB.user({
        UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
        PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
      });
      mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);
      mockUserPoolService.options.MfaConfiguration = "OPTIONAL";

      const response = await adminInitiateAuth(TestContext, {
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        AuthParameters: {
          USERNAME: existingUser.Username,
          PASSWORD: existingUser.Password,
        },
      });

      expect(response.ChallengeName).toEqual("SOFTWARE_TOKEN_MFA");
      expect(response.AuthenticationResult).toBeUndefined();
    });

    it("issues tokens directly when MfaConfiguration is OPTIONAL and user has no MFA", async () => {
      mockTokenGenerator.generate.mockResolvedValue({
        AccessToken: "access",
        IdToken: "id",
        RefreshToken: "refresh",
        ExpiresIn: 3600,
        TokenType: "Bearer",
      });
      const existingUser = TDB.user();
      mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
      mockUserPoolService.options.MfaConfiguration = "OPTIONAL";

      const response = await adminInitiateAuth(TestContext, {
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        AuthParameters: {
          USERNAME: existingUser.Username,
          PASSWORD: existingUser.Password,
        },
      });

      expect(response.AuthenticationResult?.AccessToken).toEqual("access");
    });
  });

  it("supports REFRESH_TOKEN_AUTH", async () => {
    const existingUser = TDB.user({
      RefreshTokens: ["refresh token"],
      TokenOrigins: [
        { Jti: "origin", ClientId: userPoolClient.ClientId, ExpiresAt: 4e9 },
      ],
    });
    mockTokenVerifier.verifyRefreshToken.mockResolvedValue({
      claims: { "cognito:username": existingUser.Username, jti: "origin" },
      user: existingUser,
      userPool: mockUserPoolService,
    });
    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

    const response = await adminInitiateAuth(TestContext, {
      AuthFlow: "REFRESH_TOKEN_AUTH",
      ClientId: userPoolClient.ClientId,
      UserPoolId: userPoolClient.UserPoolId,
      AuthParameters: {
        REFRESH_TOKEN: "refresh token",
      },
      ClientMetadata: {
        client: "metadata",
      },
    });

    expect(mockTokenVerifier.verifyRefreshToken).toHaveBeenCalledWith(
      TestContext,
      "refresh token",
      userPoolClient.ClientId,
    );
    expect(mockUserPoolService.storeRefreshToken).not.toHaveBeenCalled();

    expect(response.AuthenticationResult).toEqual({
      AccessToken: "access",
      IdToken: "id",
      ExpiresIn: 3600,
      TokenType: "Bearer",
    });

    expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
      TestContext,
      existingUser,
      [],
      userPoolClient,
      {
        client: "metadata",
      },
      "RefreshTokens",
      [],
      { originJti: "origin" },
    );
  });

  it("starts a CUSTOM_AUTH session with the Create round", async () => {
    const existingUser = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);
    mockTriggers.enabled.mockReturnValue(true);
    mockTriggers.defineAuthChallenge.mockResolvedValue({
      challengeName: "CUSTOM_CHALLENGE",
      issueTokens: false,
      failAuthentication: false,
    });
    mockTriggers.createAuthChallenge.mockResolvedValue({
      publicChallengeParameters: {},
      privateChallengeParameters: { secretLoginCode: "123456" },
      challengeMetadata: "CODE-123456",
    });

    const response = await adminInitiateAuth(TestContext, {
      AuthFlow: "CUSTOM_AUTH",
      ClientId: userPoolClient.ClientId,
      UserPoolId: userPoolClient.UserPoolId,
      AuthParameters: { USERNAME: existingUser.Username },
    });

    expect(response.ChallengeName).toEqual("CUSTOM_CHALLENGE");
    expect(
      authSessions.peek(response.Session as string)?.pendingChallenge,
    ).toEqual({
      challengeName: "CUSTOM_CHALLENGE",
      privateChallengeParameters: { secretLoginCode: "123456" },
      challengeMetadata: "CODE-123456",
    });
  });
});
