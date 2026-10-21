import {
  beforeEach,
  describe,
  expect,
  it,
  type Mock,
  type MockedObject,
  vi,
} from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockMessages } from "../__tests__/mockMessages";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTokenVerifier } from "../__tests__/mockTokenVerifier";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { UUID } from "../__tests__/patterns";
import { srpClient } from "../__tests__/srpClient";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  InvalidParameterError,
  NotAuthorizedError,
  PasswordResetRequiredError,
  UserNotConfirmedException,
} from "../errors";
import {
  InMemoryAuthSessions,
  InMemorySrpSessions,
  type Messages,
  type Triggers,
  type UserPoolService,
} from "../services";
import { verifyPasswordClaim } from "../services/srp";
import type { TokenGenerator } from "../services/tokenGenerator";
import type { TokenVerifier } from "../services/tokenVerifier";
import {
  attributesToRecord,
  attributeValue,
  type User,
} from "../services/userPoolService";
import { InitiateAuth, type InitiateAuthTarget } from "./initiateAuth";

describe("InitiateAuth target", () => {
  let initiateAuth: InitiateAuthTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockMessages: MockedObject<Messages>;
  let mockOtp: Mock<() => string>;
  let mockTriggers: MockedObject<Triggers>;
  let mockTokenGenerator: MockedObject<TokenGenerator>;
  let mockTokenVerifier: MockedObject<TokenVerifier>;
  let authSessions: InMemoryAuthSessions;
  let srpSessions: InMemorySrpSessions;
  let clock: ClockFake;
  const userPoolClient = TDB.appClient();

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService({
      Id: userPoolClient.UserPoolId,
    });
    mockMessages = newMockMessages();
    mockOtp = vi.fn().mockReturnValue("123456");
    mockTriggers = newMockTriggers();
    mockTokenGenerator = newMockTokenGenerator();
    mockTokenVerifier = newMockTokenVerifier();
    clock = new ClockFake(new Date());
    authSessions = new InMemoryAuthSessions(clock);
    srpSessions = new InMemorySrpSessions(clock);

    const mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockCognitoService.getAppClient.mockResolvedValue(userPoolClient);

    initiateAuth = InitiateAuth({
      authSessions,
      cognito: mockCognitoService,
      messages: mockMessages,
      otp: mockOtp,
      srpSessions,
      triggers: mockTriggers,
      tokenGenerator: mockTokenGenerator,
      tokenVerifier: mockTokenVerifier,
      clock: new ClockFake(new Date()),
    });
  });

  describe("USER_PASSWORD_AUTH auth flow", () => {
    it("throws if AuthParameters not provided", async () => {
      await expect(
        initiateAuth(TestContext, {
          ClientId: userPoolClient.ClientId,
          AuthFlow: "USER_PASSWORD_AUTH",
        }),
      ).rejects.toEqual(
        new InvalidParameterError("Missing required parameter authParameters"),
      );
    });

    it("throws if password is incorrect", async () => {
      const user = TDB.user();

      mockUserPoolService.getUserByUsername.mockResolvedValue(user);

      await expect(
        initiateAuth(TestContext, {
          ClientId: userPoolClient.ClientId,
          AuthFlow: "USER_PASSWORD_AUTH",
          AuthParameters: {
            USERNAME: user.Username,
            PASSWORD: "bad-password",
          },
        }),
      ).rejects.toEqual(
        new NotAuthorizedError("Incorrect username or password."),
      );
    });

    it("throws when user requires reset", async () => {
      const user = TDB.user({
        UserStatus: "RESET_REQUIRED",
      });

      mockUserPoolService.getUserByUsername.mockResolvedValue(user);

      await expect(
        initiateAuth(TestContext, {
          ClientId: userPoolClient.ClientId,
          AuthFlow: "USER_PASSWORD_AUTH",
          AuthParameters: {
            USERNAME: user.Username,
            PASSWORD: "bad-password",
          },
        }),
      ).rejects.toBeInstanceOf(PasswordResetRequiredError);
    });

    describe("when user doesn't exist", () => {
      describe("when User Migration trigger is enabled", () => {
        it("invokes the User Migration trigger and continues", async () => {
          mockTokenGenerator.generate.mockResolvedValue({
            AccessToken: "access",
            IdToken: "id",
            RefreshToken: "refresh",
            ExpiresIn: 3600,
            TokenType: "Bearer",
          });

          const user = TDB.user();

          mockTriggers.enabled.mockReturnValue(true);
          mockTriggers.userMigration.mockResolvedValue(user);
          mockUserPoolService.getUserByUsername.mockResolvedValue(null);

          const output = await initiateAuth(TestContext, {
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: {
              USERNAME: user.Username,
              PASSWORD: user.Password,
            },
            ClientId: userPoolClient.ClientId,
            ClientMetadata: {
              client: "metadata",
            },
          });

          expect(mockTriggers.userMigration).toHaveBeenCalledWith(TestContext, {
            clientId: userPoolClient.ClientId,
            clientMetadata: undefined,
            password: user.Password,
            userAttributes: [],
            userPoolId: userPoolClient.UserPoolId,
            username: user.Username,
            validationData: { client: "metadata" },
          });

          expect(output).toBeDefined();
          expect(output.AuthenticationResult?.AccessToken).toBeDefined();
        });
      });

      describe("when User Migration trigger is disabled", () => {
        it("throws", async () => {
          mockTriggers.enabled.mockReturnValue(false);
          mockUserPoolService.getUserByUsername.mockResolvedValue(null);

          await expect(
            initiateAuth(TestContext, {
              ClientId: userPoolClient.ClientId,
              AuthFlow: "USER_PASSWORD_AUTH",
              AuthParameters: {
                USERNAME: "username",
                PASSWORD: "password",
              },
            }),
          ).rejects.toBeInstanceOf(NotAuthorizedError);
        });
      });
    });

    describe("when password matches", () => {
      describe("when MFA is ON", () => {
        beforeEach(() => {
          mockUserPoolService.options.MfaConfiguration = "ON";
        });

        describe("when user has SMS_MFA configured", () => {
          let user: User;

          beforeEach(() => {
            user = TDB.user({
              Attributes: [
                {
                  Name: "phone_number",
                  Value: "0411000111",
                },
              ],
              MFAOptions: [
                {
                  DeliveryMedium: "SMS",
                  AttributeName: "phone_number",
                },
              ],
            });
            mockUserPoolService.getUserByUsername.mockResolvedValue(user);
          });

          it("sends MFA code to user", async () => {
            const output = await initiateAuth(TestContext, {
              ClientId: userPoolClient.ClientId,
              AuthFlow: "USER_PASSWORD_AUTH",
              AuthParameters: {
                USERNAME: user.Username,
                PASSWORD: user.Password,
              },
            });

            expect(output).toBeDefined();

            expect(mockMessages.deliver).toHaveBeenCalledWith(
              TestContext,
              "Authentication",
              userPoolClient.ClientId,
              userPoolClient.UserPoolId,
              user,
              "123456",
              undefined,
              {
                AttributeName: "phone_number",
                DeliveryMedium: "SMS",
                Destination: "0411000111",
              },
            );

            // also saves the code on the user for comparison later
            expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
              TestContext,
              {
                ...user,
                MFACode: "123456",
              },
            );
          });

          describe("when Post Authentication trigger is enabled", () => {
            it("does not invoke the trigger", async () => {
              mockTriggers.enabled.mockImplementation(
                (trigger) => trigger === "PostAuthentication",
              );

              await initiateAuth(TestContext, {
                ClientId: userPoolClient.ClientId,
                AuthFlow: "USER_PASSWORD_AUTH",
                AuthParameters: {
                  USERNAME: user.Username,
                  PASSWORD: user.Password,
                },
              });

              expect(mockTriggers.postAuthentication).not.toHaveBeenCalled();
            });
          });
        });

        describe("when user doesn't have MFA configured", () => {
          const user = TDB.user({ MFAOptions: undefined });

          beforeEach(() => {
            mockUserPoolService.getUserByUsername.mockResolvedValue(user);
          });

          it("throws an exception", async () => {
            await expect(
              initiateAuth(TestContext, {
                ClientId: userPoolClient.ClientId,
                AuthFlow: "USER_PASSWORD_AUTH",
                AuthParameters: {
                  USERNAME: user.Username,
                  PASSWORD: user.Password,
                },
              }),
            ).rejects.toBeInstanceOf(NotAuthorizedError);
          });
        });
      });

      describe("when MFA is OPTIONAL", () => {
        beforeEach(() => {
          mockUserPoolService.options.MfaConfiguration = "OPTIONAL";
        });

        describe("when user has SMS_MFA configured", () => {
          let user: User;

          beforeEach(() => {
            user = TDB.user({
              Attributes: [
                {
                  Name: "phone_number",
                  Value: "0411000111",
                },
              ],
              MFAOptions: [
                {
                  DeliveryMedium: "SMS",
                  AttributeName: "phone_number",
                },
              ],
            });
            mockUserPoolService.getUserByUsername.mockResolvedValue(user);
          });

          it("sends MFA code to user", async () => {
            const output = await initiateAuth(TestContext, {
              ClientId: userPoolClient.ClientId,
              ClientMetadata: {
                client: "metadata",
              },
              AuthFlow: "USER_PASSWORD_AUTH",
              AuthParameters: {
                USERNAME: user.Username,
                PASSWORD: user.Password,
              },
            });

            expect(output).toBeDefined();

            expect(mockMessages.deliver).toHaveBeenCalledWith(
              TestContext,
              "Authentication",
              userPoolClient.ClientId,
              userPoolClient.UserPoolId,
              user,
              "123456",
              {
                client: "metadata",
              },
              {
                AttributeName: "phone_number",
                DeliveryMedium: "SMS",
                Destination: "0411000111",
              },
            );

            // also saves the code on the user for comparison later
            expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
              TestContext,
              {
                ...user,
                MFACode: "123456",
              },
            );
          });

          describe("when Post Authentication trigger is enabled", () => {
            it("does not invoke the trigger", async () => {
              mockTriggers.enabled.mockImplementation(
                (trigger) => trigger === "PostAuthentication",
              );

              await initiateAuth(TestContext, {
                ClientId: userPoolClient.ClientId,
                AuthFlow: "USER_PASSWORD_AUTH",
                AuthParameters: {
                  USERNAME: user.Username,
                  PASSWORD: user.Password,
                },
              });

              expect(mockTriggers.postAuthentication).not.toHaveBeenCalled();
            });
          });
        });

        describe("when user doesn't have MFA configured", () => {
          const user = TDB.user({
            MFAOptions: undefined,
          });

          beforeEach(() => {
            mockUserPoolService.getUserByUsername.mockResolvedValue(user);
          });

          it("generates tokens", async () => {
            mockTokenGenerator.generate.mockResolvedValue({
              AccessToken: "access",
              IdToken: "id",
              RefreshToken: "refresh",
              ExpiresIn: 3600,
              TokenType: "Bearer",
            });
            mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

            const output = await initiateAuth(TestContext, {
              ClientId: userPoolClient.ClientId,
              AuthFlow: "USER_PASSWORD_AUTH",
              AuthParameters: {
                USERNAME: user.Username,
                PASSWORD: user.Password,
              },
              ClientMetadata: {
                client: "metadata",
              },
            });

            expect(output).toBeDefined();

            expect(output.AuthenticationResult?.AccessToken).toEqual("access");
            expect(output.AuthenticationResult?.IdToken).toEqual("id");
            expect(output.AuthenticationResult?.RefreshToken).toEqual(
              "refresh",
            );

            expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
              TestContext,
              user,
              [],
              userPoolClient,
              undefined,
              "Authentication",
            );
          });
        });
      });

      describe("when user is TOTP-enrolled but pool MfaConfiguration is unset", () => {
        it("still issues SOFTWARE_TOKEN_MFA challenge", async () => {
          // An enrolled user's UserMFASettingList is authoritative: MFA
          // must fire even when the pool has no MfaConfiguration and no
          // pool-level SoftwareTokenMfaConfiguration flag.
          const user = TDB.user({
            UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
            PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
            SoftwareTokenMfaConfiguration: { Secret: "s", Verified: true },
          });
          mockUserPoolService.getUserByUsername.mockResolvedValue(user);

          const output = await initiateAuth(TestContext, {
            ClientId: userPoolClient.ClientId,
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: {
              USERNAME: user.Username,
              PASSWORD: user.Password,
            },
          });

          expect(output.ChallengeName).toEqual("SOFTWARE_TOKEN_MFA");
          expect(output.AuthenticationResult).toBeUndefined();
        });
      });

      describe("when user has only SOFTWARE_TOKEN_MFA", () => {
        let user: User;

        beforeEach(() => {
          mockUserPoolService.options.MfaConfiguration = "OPTIONAL";
          mockUserPoolService.options.SoftwareTokenMfaConfiguration = {
            Enabled: true,
          };
          user = TDB.user({
            UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
            SoftwareTokenMfaConfiguration: {
              Secret: "SECRET",
              Verified: true,
              FriendlyDeviceName: "Phone",
            },
          });
          mockUserPoolService.getUserByUsername.mockResolvedValue(user);
        });

        it("returns SOFTWARE_TOKEN_MFA challenge", async () => {
          const output = await initiateAuth(TestContext, {
            ClientId: userPoolClient.ClientId,
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: {
              USERNAME: user.Username,
              PASSWORD: user.Password,
            },
          });

          expect(output.ChallengeName).toEqual("SOFTWARE_TOKEN_MFA");
          expect(output.ChallengeParameters).toEqual({
            USER_ID_FOR_SRP: user.Username,
            FRIENDLY_DEVICE_NAME: "Phone",
          });
          expect(output.Session).toMatch(UUID);
          expect(mockMessages.deliver).not.toHaveBeenCalled();
        });
      });

      describe("when user has both SMS_MFA and SOFTWARE_TOKEN_MFA", () => {
        let user: User;

        beforeEach(() => {
          mockUserPoolService.options.MfaConfiguration = "OPTIONAL";
          mockUserPoolService.options.SoftwareTokenMfaConfiguration = {
            Enabled: true,
          };
          user = TDB.user({
            Attributes: [{ Name: "phone_number", Value: "0411000111" }],
            MFAOptions: [
              { DeliveryMedium: "SMS", AttributeName: "phone_number" },
            ],
            UserMFASettingList: ["SMS_MFA", "SOFTWARE_TOKEN_MFA"],
            SoftwareTokenMfaConfiguration: {
              Secret: "SECRET",
              Verified: true,
            },
          });
          mockUserPoolService.getUserByUsername.mockResolvedValue(user);
        });

        it("returns SELECT_MFA_TYPE challenge", async () => {
          const output = await initiateAuth(TestContext, {
            ClientId: userPoolClient.ClientId,
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: {
              USERNAME: user.Username,
              PASSWORD: user.Password,
            },
          });

          expect(output.ChallengeName).toEqual("SELECT_MFA_TYPE");
          expect(output.ChallengeParameters?.USER_ID_FOR_SRP).toEqual(
            user.Username,
          );
          expect(
            JSON.parse(output.ChallengeParameters?.MFAS_CAN_CHOOSE ?? "[]"),
          ).toEqual(["SMS_MFA", "SOFTWARE_TOKEN_MFA"]);
          expect(output.Session).toMatch(UUID);
          expect(mockMessages.deliver).not.toHaveBeenCalled();
        });
      });

      describe("when MFA is OFF", () => {
        const user = TDB.user();

        beforeEach(() => {
          mockUserPoolService.options.MfaConfiguration = "OFF";
          mockUserPoolService.getUserByUsername.mockResolvedValue(user);
        });

        it("generates tokens", async () => {
          mockTokenGenerator.generate.mockResolvedValue({
            AccessToken: "access",
            IdToken: "id",
            RefreshToken: "refresh",
            ExpiresIn: 3600,
            TokenType: "Bearer",
          });
          mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

          const output = await initiateAuth(TestContext, {
            ClientId: userPoolClient.ClientId,
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: {
              USERNAME: user.Username,
              PASSWORD: user.Password,
            },
            ClientMetadata: {
              client: "metadata",
            },
          });

          expect(output).toBeDefined();

          expect(output.AuthenticationResult?.AccessToken).toEqual("access");
          expect(output.AuthenticationResult?.IdToken).toEqual("id");
          expect(output.AuthenticationResult?.RefreshToken).toEqual("refresh");

          expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
            TestContext,
            user,
            [],
            userPoolClient,
            undefined,
            "Authentication",
          );
        });

        describe("when Post Authentication trigger is enabled", () => {
          it("invokes the trigger before generating tokens", async () => {
            mockTokenGenerator.generate.mockResolvedValue({
              AccessToken: "access",
              IdToken: "id",
              RefreshToken: "refresh",
              ExpiresIn: 3600,
              TokenType: "Bearer",
            });

            mockTriggers.enabled.mockImplementation(
              (trigger) => trigger === "PostAuthentication",
            );

            await initiateAuth(TestContext, {
              ClientId: userPoolClient.ClientId,
              AuthFlow: "USER_PASSWORD_AUTH",
              AuthParameters: {
                USERNAME: user.Username,
                PASSWORD: user.Password,
              },
            });

            expect(mockTriggers.postAuthentication).toHaveBeenCalledWith(
              TestContext,
              {
                clientId: userPoolClient.ClientId,
                source: "PostAuthentication_Authentication",
                userAttributes: user.Attributes,
                username: user.Username,
                userPoolId: userPoolClient.UserPoolId,
              },
            );

            expect(mockTriggers.postAuthentication).toHaveBeenCalledBefore(
              mockTokenGenerator.generate,
            );
          });
        });
      });
    });

    describe("when user status is FORCE_CHANGE_PASSWORD", () => {
      const user = TDB.user({
        UserStatus: "FORCE_CHANGE_PASSWORD",
      });

      beforeEach(() => {
        mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      });

      it("responds with a NEW_PASSWORD_REQUIRED challenge", async () => {
        const response = await initiateAuth(TestContext, {
          ClientId: userPoolClient.ClientId,
          AuthFlow: "USER_PASSWORD_AUTH",
          AuthParameters: {
            USERNAME: user.Username,
            PASSWORD: "bad-password",
          },
        });

        expect(response).toEqual({
          ChallengeName: "NEW_PASSWORD_REQUIRED",
          ChallengeParameters: {
            USER_ID_FOR_SRP: user.Username,
            requiredAttributes: "[]",
            userAttributes: JSON.stringify(attributesToRecord(user.Attributes)),
          },
          Session: expect.stringMatching(UUID),
        });
      });

      describe("when Post Authentication trigger is enabled", () => {
        it("does not invoke the trigger", async () => {
          mockTriggers.enabled.mockImplementation(
            (trigger) => trigger === "PostAuthentication",
          );

          await initiateAuth(TestContext, {
            ClientId: userPoolClient.ClientId,
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: {
              USERNAME: user.Username,
              PASSWORD: user.Password,
            },
          });

          expect(mockTriggers.postAuthentication).not.toHaveBeenCalled();
        });
      });
    });
  });

  describe("USER_SRP_AUTH auth flow", () => {
    const user = TDB.user({ Password: "Example-Passw0rd!" });

    beforeEach(() => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    });

    it("returns a PASSWORD_VERIFIER challenge only the right password can answer", async () => {
      const client = srpClient(userPoolClient.UserPoolId);
      const output = await initiateAuth(TestContext, {
        ClientId: userPoolClient.ClientId,
        AuthFlow: "USER_SRP_AUTH",
        AuthParameters: { USERNAME: user.Username, SRP_A: client.srpA },
      });

      expect(output.ChallengeName).toEqual("PASSWORD_VERIFIER");
      const challenge = output.ChallengeParameters as Record<string, string>;
      expect(challenge).toEqual({
        SALT: expect.stringMatching(/^[0-9a-f]{32}$/),
        SRP_B: expect.stringMatching(/^[0-9a-f]+$/),
        SECRET_BLOCK: expect.any(String),
        USER_ID_FOR_SRP: user.Username,
        USERNAME: user.Username,
      });
      expect(() =>
        verifyPasswordClaim(srpSessions, {
          userPoolId: userPoolClient.UserPoolId,
          clientId: userPoolClient.ClientId,
          user,
          challengeResponses: client.respond(challenge, "wrong-password"),
        }),
      ).toThrow(new NotAuthorizedError("Incorrect username or password."));
    });

    it("throws if SRP_A is missing", async () => {
      await expect(
        initiateAuth(TestContext, {
          ClientId: userPoolClient.ClientId,
          AuthFlow: "USER_SRP_AUTH",
          AuthParameters: { USERNAME: user.Username },
        }),
      ).rejects.toEqual(
        new InvalidParameterError("Missing required parameter SRP_A"),
      );
    });

    it("throws UserNotConfirmed for an unconfirmed user", async () => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(
        TDB.user({ UserStatus: "UNCONFIRMED" }),
      );

      await expect(
        initiateAuth(TestContext, {
          ClientId: userPoolClient.ClientId,
          AuthFlow: "USER_SRP_AUTH",
          AuthParameters: {
            USERNAME: user.Username,
            SRP_A: srpClient(userPoolClient.UserPoolId).srpA,
          },
        }),
      ).rejects.toBeInstanceOf(UserNotConfirmedException);
    });
  });

  describe("REFRESH_TOKEN_AUTH auth flow", () => {
    const existingUser = TDB.user({
      RefreshTokens: ["refresh token"],
      TokenOrigins: [
        { Jti: "origin", ClientId: userPoolClient.ClientId, ExpiresAt: 4e9 },
      ],
    });

    beforeEach(() => {
      mockTokenVerifier.verifyRefreshToken.mockResolvedValue({
        claims: { "cognito:username": existingUser.Username, jti: "origin" },
        user: existingUser,
        userPool: mockUserPoolService,
      });
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
    });

    it("returns new tokens in the refresh token's session", async () => {
      const response = await initiateAuth(TestContext, {
        AuthFlow: "REFRESH_TOKEN_AUTH",
        ClientId: userPoolClient.ClientId,
        AuthParameters: {
          REFRESH_TOKEN: "refresh token",
        },
        ClientMetadata: {
          client: "metadata",
        },
      });

      expect(response.AuthenticationResult).toEqual({
        AccessToken: "access",
        IdToken: "id",
        ExpiresIn: 3600,
        TokenType: "Bearer",
      });
      expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
      expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
        TestContext,
        existingUser,
        [],
        userPoolClient,
        undefined,
        "RefreshTokens",
        [],
        { originJti: "origin" },
      );
    });

    it("registers the session of a refresh token issued before sessions were tracked", async () => {
      const legacyUser = { ...existingUser, TokenOrigins: undefined };
      mockTokenVerifier.verifyRefreshToken.mockResolvedValue({
        claims: {
          "cognito:username": legacyUser.Username,
          jti: "legacy",
          exp: 4e9,
        },
        user: legacyUser,
        userPool: mockUserPoolService,
      });

      await initiateAuth(TestContext, {
        AuthFlow: "REFRESH_TOKEN_AUTH",
        ClientId: userPoolClient.ClientId,
        AuthParameters: { REFRESH_TOKEN: "refresh token" },
      });

      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
        ...legacyUser,
        TokenOrigins: [
          { Jti: "legacy", ClientId: userPoolClient.ClientId, ExpiresAt: 4e9 },
        ],
      });
    });

    it("checks SECRET_HASH against the user's sub when username is not a sign-in attribute", async () => {
      mockUserPoolService.options.UsernameAttributes = ["email"];

      await initiateAuth(TestContext, {
        AuthFlow: "REFRESH_TOKEN_AUTH",
        ClientId: userPoolClient.ClientId,
        AuthParameters: { REFRESH_TOKEN: "refresh token", SECRET_HASH: "hash" },
      });

      expect(mockTokenVerifier.verifySecretHash).toHaveBeenCalledWith(
        userPoolClient,
        [attributeValue("sub", existingUser.Attributes)],
        "hash",
      );
    });

    it("checks SECRET_HASH against the username when username is a sign-in attribute", async () => {
      await initiateAuth(TestContext, {
        AuthFlow: "REFRESH_TOKEN_AUTH",
        ClientId: userPoolClient.ClientId,
        AuthParameters: { REFRESH_TOKEN: "refresh token", SECRET_HASH: "hash" },
      });

      expect(mockTokenVerifier.verifySecretHash).toHaveBeenCalledWith(
        userPoolClient,
        [existingUser.Username],
        "hash",
      );
    });
  });

  it("checks SECRET_HASH against USERNAME before a sign-in flow", async () => {
    mockTokenVerifier.verifySecretHash.mockImplementation(() => {
      throw new NotAuthorizedError("Unable to verify secret hash");
    });

    await expect(
      initiateAuth(TestContext, {
        AuthFlow: "USER_PASSWORD_AUTH",
        ClientId: userPoolClient.ClientId,
        AuthParameters: { USERNAME: "u", PASSWORD: "p", SECRET_HASH: "bad" },
      }),
    ).rejects.toEqual(new NotAuthorizedError("Unable to verify secret hash"));
    expect(mockTokenVerifier.verifySecretHash).toHaveBeenCalledWith(
      userPoolClient,
      ["u"],
      "bad",
    );
    expect(mockUserPoolService.getUserByUsername).not.toHaveBeenCalled();
  });

  describe("CUSTOM_AUTH auth flow", () => {
    const user = TDB.user();

    beforeEach(() => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      mockTriggers.enabled.mockReturnValue(true);
      mockTriggers.createAuthChallenge.mockResolvedValue({
        publicChallengeParameters: { email: "e@example.com" },
        privateChallengeParameters: { secretLoginCode: "123456" },
        challengeMetadata: "CODE-123456",
      });
    });

    it("runs Define then Create and stores the round in a session", async () => {
      mockTriggers.defineAuthChallenge.mockResolvedValue({
        challengeName: "CUSTOM_CHALLENGE",
        issueTokens: false,
        failAuthentication: false,
      });

      const output = await initiateAuth(TestContext, {
        ClientId: userPoolClient.ClientId,
        AuthFlow: "CUSTOM_AUTH",
        AuthParameters: { USERNAME: user.Username },
        ClientMetadata: { client: "metadata" },
      });

      expect(mockTriggers.defineAuthChallenge).toHaveBeenCalledWith(
        TestContext,
        {
          clientId: userPoolClient.ClientId,
          userAttributes: user.Attributes,
          username: user.Username,
          userPoolId: userPoolClient.UserPoolId,
          session: [],
          clientMetadata: { client: "metadata" },
        },
      );
      expect(mockTriggers.createAuthChallenge).toHaveBeenCalledWith(
        TestContext,
        expect.objectContaining({
          challengeName: "CUSTOM_CHALLENGE",
          session: [],
        }),
      );
      expect(output.ChallengeName).toEqual("CUSTOM_CHALLENGE");
      expect(output.ChallengeParameters).toEqual({
        email: "e@example.com",
        USERNAME: user.Username,
        USER_ID_FOR_SRP: user.Username,
      });
      expect(authSessions.peek(output.Session as string)).toEqual({
        userPoolId: userPoolClient.UserPoolId,
        clientId: userPoolClient.ClientId,
        username: user.Username,
        clientMetadata: { client: "metadata" },
        history: [],
        pendingChallenge: {
          challengeName: "CUSTOM_CHALLENGE",
          privateChallengeParameters: { secretLoginCode: "123456" },
          challengeMetadata: "CODE-123456",
        },
      });
    });

    it("keeps the session for the client's AuthSessionValidity", async () => {
      mockTriggers.defineAuthChallenge.mockResolvedValue({
        challengeName: "CUSTOM_CHALLENGE",
        issueTokens: false,
        failAuthentication: false,
      });
      const longSessionClient = { ...userPoolClient, AuthSessionValidity: 10 };
      const cognito = newMockCognitoService(mockUserPoolService);
      cognito.getAppClient.mockResolvedValue(longSessionClient);
      const target = InitiateAuth({
        authSessions,
        cognito,
        messages: mockMessages,
        otp: mockOtp,
        srpSessions,
        triggers: mockTriggers,
        tokenGenerator: mockTokenGenerator,
        tokenVerifier: newMockTokenVerifier(),
        clock: new ClockFake(new Date()),
      });

      const output = await target(TestContext, {
        ClientId: longSessionClient.ClientId,
        AuthFlow: "CUSTOM_AUTH",
        AuthParameters: { USERNAME: user.Username },
      });

      clock.advanceBy(10 * 60_000 - 1);
      expect(authSessions.peek(output.Session as string)).toBeDefined();
      clock.advanceBy(1);
      expect(authSessions.peek(output.Session as string)).toBeUndefined();
    });

    it("issues tokens when Define says so without a challenge", async () => {
      mockTriggers.defineAuthChallenge.mockResolvedValue({
        challengeName: "",
        issueTokens: true,
        failAuthentication: false,
      });
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
      mockTokenGenerator.generate.mockResolvedValue({
        AccessToken: "access",
        IdToken: "id",
        RefreshToken: "refresh",
        ExpiresIn: 3600,
        TokenType: "Bearer",
      });

      const output = await initiateAuth(TestContext, {
        ClientId: userPoolClient.ClientId,
        AuthFlow: "CUSTOM_AUTH",
        AuthParameters: { USERNAME: user.Username },
      });

      expect(output.AuthenticationResult?.IdToken).toEqual("id");
      expect(mockTriggers.createAuthChallenge).not.toHaveBeenCalled();
    });

    it("throws NotAuthorized when Define fails authentication", async () => {
      mockTriggers.defineAuthChallenge.mockResolvedValue({
        challengeName: "",
        issueTokens: false,
        failAuthentication: true,
      });

      await expect(
        initiateAuth(TestContext, {
          ClientId: userPoolClient.ClientId,
          AuthFlow: "CUSTOM_AUTH",
          AuthParameters: { USERNAME: user.Username },
        }),
      ).rejects.toBeInstanceOf(NotAuthorizedError);
    });

    it("starts the history with SRP_A and returns PASSWORD_VERIFIER when Define asks for it", async () => {
      mockTriggers.defineAuthChallenge.mockResolvedValue({
        challengeName: "PASSWORD_VERIFIER",
        issueTokens: false,
        failAuthentication: false,
      });

      const output = await initiateAuth(TestContext, {
        ClientId: userPoolClient.ClientId,
        AuthFlow: "CUSTOM_AUTH",
        AuthParameters: {
          USERNAME: user.Username,
          SRP_A: srpClient(userPoolClient.UserPoolId).srpA,
        },
      });

      expect(mockTriggers.defineAuthChallenge).toHaveBeenCalledWith(
        TestContext,
        expect.objectContaining({
          session: [{ challengeName: "SRP_A", challengeResult: true }],
        }),
      );
      expect(output.ChallengeName).toEqual("PASSWORD_VERIFIER");
      expect(output.ChallengeParameters?.USERNAME).toEqual(user.Username);
      expect(
        authSessions.peek(output.Session as string)?.pendingChallenge
          .challengeName,
      ).toEqual("PASSWORD_VERIFIER");
    });
  });
});
