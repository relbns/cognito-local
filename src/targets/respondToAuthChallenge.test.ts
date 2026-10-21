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
import { srpClient } from "../__tests__/srpClient";
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
  InMemorySrpSessions,
  type Messages,
  type Triggers,
  type UserPoolService,
} from "../services";
import { startPasswordVerifier } from "../services/srp";
import type { TokenGenerator } from "../services/tokenGenerator";
import { generateSecret, generate as genTotp } from "../services/totp";
import {
  RespondToAuthChallenge,
  type RespondToAuthChallengeTarget,
} from "./respondToAuthChallenge";

const currentDate = new Date();

describe("RespondToAuthChallenge target", () => {
  let respondToAuthChallenge: RespondToAuthChallengeTarget;
  let mockTokenGenerator: MockedObject<TokenGenerator>;
  let mockTriggers: MockedObject<Triggers>;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockMessages: MockedObject<Messages>;
  let mockOtp: Mock<() => string>;
  let clock: ClockFake;
  let authSessions: InMemoryAuthSessions;
  let srpSessions: InMemorySrpSessions;
  const userPoolClient = TDB.appClient();

  beforeEach(() => {
    clock = new ClockFake(currentDate);
    mockTokenGenerator = newMockTokenGenerator();
    mockTriggers = newMockTriggers();
    mockUserPoolService = newMockUserPoolService({
      Id: userPoolClient.UserPoolId,
    });
    mockMessages = newMockMessages();
    mockOtp = vi.fn().mockReturnValue("123456");

    const mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockCognitoService.getAppClient.mockResolvedValue(userPoolClient);

    authSessions = new InMemoryAuthSessions(clock);
    srpSessions = new InMemorySrpSessions(clock);
    respondToAuthChallenge = RespondToAuthChallenge({
      authSessions,
      clock,
      cognito: mockCognitoService,
      messages: mockMessages,
      otp: mockOtp,
      srpSessions,
      tokenGenerator: mockTokenGenerator,
      tokenVerifier: newMockTokenVerifier(),
      triggers: mockTriggers,
    });
  });

  it("throws if user doesn't exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      respondToAuthChallenge(TestContext, {
        ClientId: "clientId",
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
      respondToAuthChallenge(TestContext, {
        ClientId: "clientId",
        ChallengeName: "SMS_MFA",
      }),
    ).rejects.toEqual(
      new InvalidParameterError(
        "Missing required parameter challenge responses",
      ),
    );
  });

  it("throws if ChallengeResponses.USERNAME is missing", async () => {
    await expect(
      respondToAuthChallenge(TestContext, {
        ClientId: "clientId",
        ChallengeName: "SMS_MFA",
        ChallengeResponses: {},
      }),
    ).rejects.toEqual(
      new InvalidParameterError("Missing required parameter USERNAME"),
    );
  });

  it("throws if Session is missing", async () => {
    // we don't actually do anything with the session right now, but we still want to
    // replicate Cognito's behaviour if you don't provide it
    await expect(
      respondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        ChallengeName: "SMS_MFA",
        ChallengeResponses: {
          USERNAME: "abc",
        },
      }),
    ).rejects.toEqual(
      new InvalidParameterError("Missing required parameter Session"),
    );
  });

  describe("ChallengeName=SMS_MFA", () => {
    const user = TDB.user({
      MFACode: "123456",
    });

    beforeEach(() => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    });

    describe("when code matches", () => {
      it("updates the user and removes the MFACode", async () => {
        const newDate = clock.advanceBy(1200);

        await respondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
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
          ExpiresIn: 3600,
          TokenType: "Bearer",
        });
        mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

        const output = await respondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          ChallengeName: "SMS_MFA",
          ChallengeResponses: {
            USERNAME: user.Username,
            SMS_MFA_CODE: "123456",
          },
          Session: "Session",
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
          { ...user, MFACode: undefined, UserLastModifiedDate: clock.get() },
          [],
          userPoolClient,
          {
            client: "metadata",
          },
          "Authentication",
        );
      });

      describe("when Post Authentication trigger is enabled", () => {
        it("does invokes the trigger", async () => {
          mockTriggers.enabled.mockImplementation(
            (trigger) => trigger === "PostAuthentication",
          );

          await respondToAuthChallenge(TestContext, {
            ClientId: userPoolClient.ClientId,
            ChallengeName: "SMS_MFA",
            ClientMetadata: {
              client: "metadata",
            },
            ChallengeResponses: {
              USERNAME: user.Username,
              SMS_MFA_CODE: "123456",
            },
            Session: "Session",
          });

          expect(mockTriggers.postAuthentication).toHaveBeenCalledWith(
            TestContext,
            {
              clientId: userPoolClient.ClientId,
              clientMetadata: {
                client: "metadata",
              },
              source: "PostAuthentication_Authentication",
              userAttributes: user.Attributes,
              username: user.Username,
              userPoolId: userPoolClient.UserPoolId,
            },
          );
        });
      });
    });

    describe("when code is incorrect", () => {
      it("throws an error", async () => {
        mockUserPoolService.getUserByUsername.mockResolvedValue(user);

        await expect(
          respondToAuthChallenge(TestContext, {
            ClientId: userPoolClient.ClientId,
            ChallengeName: "SMS_MFA",
            ChallengeResponses: {
              USERNAME: user.Username,
              SMS_MFA_CODE: "4321",
            },
            Session: "Session",
          }),
        ).rejects.toBeInstanceOf(CodeMismatchError);
      });
    });
  });

  describe("ChallengeName=NEW_PASSWORD_REQUIRED", () => {
    const user = TDB.user();

    beforeEach(() => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    });

    it("throws if NEW_PASSWORD missing", async () => {
      await expect(
        respondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          ChallengeName: "NEW_PASSWORD_REQUIRED",
          ChallengeResponses: {
            USERNAME: user.Username,
          },
          Session: "session",
        }),
      ).rejects.toEqual(
        new InvalidParameterError("Missing required parameter NEW_PASSWORD"),
      );
    });

    it("rejects a new password that breaks the password policy", async () => {
      await expect(
        respondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
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

      await respondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        ChallengeName: "NEW_PASSWORD_REQUIRED",
        ChallengeResponses: {
          USERNAME: user.Username,
          NEW_PASSWORD: "foo-Aa1!",
        },
        Session: "Session",
      });

      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
        ...user,
        Password: "foo-Aa1!",
        UserLastModifiedDate: newDate,
        UserStatus: "CONFIRMED",
      });
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

      const output = await respondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        ChallengeName: "NEW_PASSWORD_REQUIRED",
        ChallengeResponses: {
          USERNAME: user.Username,
          NEW_PASSWORD: "foo-Aa1!",
        },
        Session: "Session",
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
        {
          ...user,
          Password: "foo-Aa1!",
          UserLastModifiedDate: clock.get(),
          UserStatus: "CONFIRMED",
        },
        [],
        userPoolClient,
        { client: "metadata" },
        "NewPasswordChallenge",
      );
    });

    describe("when Post Authentication trigger is enabled", () => {
      it("does invokes the trigger", async () => {
        mockTriggers.enabled.mockImplementation(
          (trigger) => trigger === "PostAuthentication",
        );

        await respondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          ChallengeName: "NEW_PASSWORD_REQUIRED",
          ChallengeResponses: {
            USERNAME: user.Username,
            NEW_PASSWORD: "foo-Aa1!",
          },
          Session: "Session",
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
      });
    });
  });

  describe("SOFTWARE_TOKEN_MFA challenge", () => {
    const secret = generateSecret();

    it("issues tokens when code matches verified secret", async () => {
      const user = TDB.user({
        UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
        SoftwareTokenMfaConfiguration: { Secret: secret, Verified: true },
      });
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
      mockTokenGenerator.generate.mockResolvedValue({
        AccessToken: "a",
        IdToken: "i",
        RefreshToken: "r",
        ExpiresIn: 3600,
        TokenType: "Bearer",
      });
      const result = await respondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        ChallengeName: "SOFTWARE_TOKEN_MFA",
        Session: "sess",
        ChallengeResponses: {
          USERNAME: user.Username,
          SOFTWARE_TOKEN_MFA_CODE: genTotp(secret),
        },
      });

      expect(result.AuthenticationResult?.AccessToken).toEqual("a");
    });

    it("rejects an incorrect code", async () => {
      const user = TDB.user({
        SoftwareTokenMfaConfiguration: { Secret: secret, Verified: true },
      });
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);

      await expect(
        respondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          ChallengeName: "SOFTWARE_TOKEN_MFA",
          Session: "sess",
          ChallengeResponses: {
            USERNAME: user.Username,
            SOFTWARE_TOKEN_MFA_CODE: "000000",
          },
        }),
      ).rejects.toBeInstanceOf(CodeMismatchError);
    });
  });

  describe("SELECT_MFA_TYPE challenge", () => {
    it("routes ANSWER=SOFTWARE_TOKEN_MFA to a TOTP challenge", async () => {
      const user = TDB.user({
        UserMFASettingList: ["SMS_MFA", "SOFTWARE_TOKEN_MFA"],
        SoftwareTokenMfaConfiguration: {
          Secret: "S",
          Verified: true,
          FriendlyDeviceName: "Phone",
        },
      });
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);

      const result = await respondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        ChallengeName: "SELECT_MFA_TYPE",
        Session: "sess",
        ChallengeResponses: {
          USERNAME: user.Username,
          ANSWER: "SOFTWARE_TOKEN_MFA",
        },
      });

      expect(result.ChallengeName).toEqual("SOFTWARE_TOKEN_MFA");
      expect(result.ChallengeParameters).toMatchObject({
        USER_ID_FOR_SRP: user.Username,
        FRIENDLY_DEVICE_NAME: "Phone",
      });
    });

    it("routes ANSWER=SMS_MFA to SMS challenge and sends code", async () => {
      const user = TDB.user({
        Attributes: [{ Name: "phone_number", Value: "0411000111" }],
        MFAOptions: [{ DeliveryMedium: "SMS", AttributeName: "phone_number" }],
        UserMFASettingList: ["SMS_MFA", "SOFTWARE_TOKEN_MFA"],
      });
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);

      const result = await respondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        ChallengeName: "SELECT_MFA_TYPE",
        Session: "sess",
        ChallengeResponses: {
          USERNAME: user.Username,
          ANSWER: "SMS_MFA",
        },
      });

      expect(result.ChallengeName).toEqual("SMS_MFA");
      expect(mockMessages.deliver).toHaveBeenCalled();
      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
        TestContext,
        expect.objectContaining({ MFACode: "123456" }),
      );
    });

    it("rejects an unknown ANSWER", async () => {
      const user = TDB.user();
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);

      await expect(
        respondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          ChallengeName: "SELECT_MFA_TYPE",
          Session: "sess",
          ChallengeResponses: {
            USERNAME: user.Username,
            ANSWER: "BOGUS",
          },
        }),
      ).rejects.toBeInstanceOf(InvalidParameterError);
    });
  });
  describe("CUSTOM_CHALLENGE challenge", () => {
    const user = TDB.user();
    const tokens = {
      AccessToken: "access",
      IdToken: "id",
      RefreshToken: "refresh",
      ExpiresIn: 3600,
      TokenType: "Bearer" as const,
    };

    const seedSession = (
      history: {
        challengeName: string;
        challengeResult: boolean;
        challengeMetadata?: string;
      }[] = [],
    ) =>
      authSessions.create({
        userPoolId: userPoolClient.UserPoolId,
        clientId: userPoolClient.ClientId,
        username: user.Username,
        history,
        pendingChallenge: {
          challengeName: "CUSTOM_CHALLENGE",
          privateChallengeParameters: { secretLoginCode: "123456" },
          challengeMetadata: "CODE-123456",
        },
      });

    const respond = (session: string, answer: string) =>
      respondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        ChallengeName: "CUSTOM_CHALLENGE",
        ChallengeResponses: { USERNAME: user.Username, ANSWER: answer },
        Session: session,
        ClientMetadata: { client: "metadata" },
      });

    beforeEach(() => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
      mockTokenGenerator.generate.mockResolvedValue(tokens);
      mockTriggers.enabled.mockImplementation(
        (name) => name !== "PostAuthentication",
      );
      mockTriggers.defineAuthChallenge.mockImplementation(
        async (_ctx, { session }) => {
          const last = session.at(-1);
          if (session.length >= 3 && last?.challengeResult === false) {
            return {
              challengeName: "",
              issueTokens: false,
              failAuthentication: true,
            };
          }
          if (last?.challengeResult === true) {
            return {
              challengeName: "",
              issueTokens: true,
              failAuthentication: false,
            };
          }
          return {
            challengeName: "CUSTOM_CHALLENGE",
            issueTokens: false,
            failAuthentication: false,
          };
        },
      );
      mockTriggers.createAuthChallenge.mockImplementation(
        async (_ctx, { session }) => {
          const code =
            session.at(-1)?.challengeMetadata?.replace("CODE-", "") ?? "123456";
          return {
            publicChallengeParameters: { hint: "code" },
            privateChallengeParameters: { secretLoginCode: code },
            challengeMetadata: `CODE-${code}`,
          };
        },
      );
      mockTriggers.verifyAuthChallengeResponse.mockImplementation(
        async (_ctx, { challengeAnswer, privateChallengeParameters }) => ({
          answerCorrect:
            challengeAnswer === privateChallengeParameters?.secretLoginCode,
        }),
      );
    });

    it("issues tokens for a correct answer and passes privateChallengeParameters to Verify", async () => {
      const output = await respond(seedSession(), "123456");

      expect(output.AuthenticationResult).toEqual(tokens);
      expect(mockTriggers.verifyAuthChallengeResponse).toHaveBeenCalledWith(
        TestContext,
        {
          clientId: userPoolClient.ClientId,
          userAttributes: user.Attributes,
          username: user.Username,
          userPoolId: userPoolClient.UserPoolId,
          challengeAnswer: "123456",
          privateChallengeParameters: { secretLoginCode: "123456" },
          clientMetadata: { client: "metadata" },
        },
      );
      expect(mockTriggers.defineAuthChallenge).toHaveBeenCalledWith(
        TestContext,
        expect.objectContaining({
          session: [
            {
              challengeName: "CUSTOM_CHALLENGE",
              challengeResult: true,
              challengeMetadata: "CODE-123456",
            },
          ],
        }),
      );
      expect(mockUserPoolService.storeRefreshToken).toHaveBeenCalledWith(
        TestContext,
        "refresh",
        user,
      );
    });

    it("returns a new challenge after a wrong answer, then issues tokens on the next round", async () => {
      const first = await respond(seedSession(), "000000");

      expect(first.AuthenticationResult).toBeUndefined();
      expect(first.ChallengeName).toEqual("CUSTOM_CHALLENGE");
      expect(first.ChallengeParameters).toEqual({
        hint: "code",
        USERNAME: user.Username,
        USER_ID_FOR_SRP: user.Username,
      });
      expect(first.Session).toBeDefined();
      expect(mockTriggers.createAuthChallenge).toHaveBeenCalledWith(
        TestContext,
        expect.objectContaining({
          challengeName: "CUSTOM_CHALLENGE",
          session: [
            {
              challengeName: "CUSTOM_CHALLENGE",
              challengeResult: false,
              challengeMetadata: "CODE-123456",
            },
          ],
        }),
      );

      const second = await respond(first.Session as string, "123456");

      expect(second.AuthenticationResult).toEqual(tokens);
      expect(mockTriggers.defineAuthChallenge).toHaveBeenLastCalledWith(
        TestContext,
        expect.objectContaining({
          session: [
            {
              challengeName: "CUSTOM_CHALLENGE",
              challengeResult: false,
              challengeMetadata: "CODE-123456",
            },
            {
              challengeName: "CUSTOM_CHALLENGE",
              challengeResult: true,
              challengeMetadata: "CODE-123456",
            },
          ],
        }),
      );
    });

    it("throws NotAuthorized when Define fails authentication after three wrong answers", async () => {
      const first = await respond(seedSession(), "bad");
      const second = await respond(first.Session as string, "bad");

      await expect(respond(second.Session as string, "bad")).rejects.toEqual(
        new NotAuthorizedError("Incorrect username or password."),
      );
      expect(mockTriggers.defineAuthChallenge).toHaveBeenCalledTimes(3);
      expect(mockTokenGenerator.generate).not.toHaveBeenCalled();
    });

    it("throws NotAuthorized for an unknown session", async () => {
      await expect(respond("unknown", "123456")).rejects.toEqual(
        new NotAuthorizedError("Invalid session for the user."),
      );
      expect(mockTriggers.verifyAuthChallengeResponse).not.toHaveBeenCalled();
    });

    it("throws NotAuthorized for an expired session", async () => {
      const session = seedSession();
      clock.advanceBy(3 * 60_000);

      await expect(respond(session, "123456")).rejects.toEqual(
        new NotAuthorizedError(
          "Invalid session for the user, session is expired.",
        ),
      );
    });

    it("does not accept the same session twice", async () => {
      const session = seedSession();
      await respond(session, "000000");

      await expect(respond(session, "123456")).rejects.toBeInstanceOf(
        NotAuthorizedError,
      );
    });

    it("rejects a session that belongs to another user", async () => {
      const session = seedSession();
      mockUserPoolService.getUserByUsername.mockResolvedValue(TDB.user());

      await expect(respond(session, "123456")).rejects.toEqual(
        new NotAuthorizedError("Invalid session for the user."),
      );
    });

    it("continues into the custom challenge after PASSWORD_VERIFIER in a CUSTOM_AUTH session", async () => {
      mockTriggers.defineAuthChallenge.mockResolvedValueOnce({
        challengeName: "CUSTOM_CHALLENGE",
        issueTokens: false,
        failAuthentication: false,
      });
      const { session, client, challenge } = seedPasswordVerifierSession();

      const output = await respondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        ChallengeName: "PASSWORD_VERIFIER",
        ChallengeResponses: client.respond(challenge, user.Password as string),
        Session: session,
      });

      expect(output.ChallengeName).toEqual("CUSTOM_CHALLENGE");
      expect(mockTriggers.defineAuthChallenge).toHaveBeenCalledWith(
        TestContext,
        expect.objectContaining({
          session: [
            { challengeName: "SRP_A", challengeResult: true },
            { challengeName: "PASSWORD_VERIFIER", challengeResult: true },
          ],
        }),
      );
    });

    it("fails a CUSTOM_AUTH PASSWORD_VERIFIER signed with a wrong password", async () => {
      const { session, client, challenge } = seedPasswordVerifierSession();

      await expect(
        respondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          ChallengeName: "PASSWORD_VERIFIER",
          ChallengeResponses: client.respond(challenge, "wrong-password"),
          Session: session,
        }),
      ).rejects.toEqual(
        new NotAuthorizedError("Incorrect username or password."),
      );
      expect(mockTriggers.defineAuthChallenge).not.toHaveBeenCalled();
    });

    const seedPasswordVerifierSession = () => {
      const client = srpClient(userPoolClient.UserPoolId);
      const challenge = startPasswordVerifier(srpSessions, {
        userPoolId: userPoolClient.UserPoolId,
        clientId: userPoolClient.ClientId,
        user,
        srpA: client.srpA,
      });
      const session = authSessions.create({
        userPoolId: userPoolClient.UserPoolId,
        clientId: userPoolClient.ClientId,
        username: user.Username,
        history: [{ challengeName: "SRP_A", challengeResult: true }],
        srpA: client.srpA,
        pendingChallenge: {
          challengeName: "PASSWORD_VERIFIER",
          privateChallengeParameters: {},
        },
      });
      return { session, client, challenge };
    };
  });

  describe("PASSWORD_VERIFIER", () => {
    const user = TDB.user({ Password: "Example-Passw0rd!" });

    beforeEach(() => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      mockTokenGenerator.generate.mockResolvedValue({
        AccessToken: "access",
        IdToken: "id",
        RefreshToken: "refresh",
        ExpiresIn: 3600,
        TokenType: "Bearer",
      });
    });

    const passwordVerifier = (password: string, target = user) => {
      const client = srpClient(userPoolClient.UserPoolId);
      const challenge = startPasswordVerifier(srpSessions, {
        userPoolId: userPoolClient.UserPoolId,
        clientId: userPoolClient.ClientId,
        user: target,
        srpA: client.srpA,
      });
      return client.respond(challenge, password);
    };

    it("issues tokens for a claim made with the right password", async () => {
      const output = await respondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        ChallengeName: "PASSWORD_VERIFIER",
        ChallengeResponses: passwordVerifier("Example-Passw0rd!"),
        Session: "Session",
      });

      expect(output.AuthenticationResult?.AccessToken).toEqual("access");
    });

    it("accepts the claim without a Session, as SRP clients may send it", async () => {
      const output = await respondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        ChallengeName: "PASSWORD_VERIFIER",
        ChallengeResponses: passwordVerifier("Example-Passw0rd!"),
      });

      expect(output.AuthenticationResult?.AccessToken).toEqual("access");
    });

    it("throws NotAuthorized for a claim made with a wrong password", async () => {
      await expect(
        respondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          ChallengeName: "PASSWORD_VERIFIER",
          ChallengeResponses: passwordVerifier("wrong-password"),
          Session: "Session",
        }),
      ).rejects.toEqual(
        new NotAuthorizedError("Incorrect username or password."),
      );
      expect(mockTokenGenerator.generate).not.toHaveBeenCalled();
    });

    it("throws NotAuthorized for a forged signature", async () => {
      await expect(
        respondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          ChallengeName: "PASSWORD_VERIFIER",
          ChallengeResponses: {
            ...passwordVerifier("Example-Passw0rd!"),
            PASSWORD_CLAIM_SIGNATURE: "c2lnbmF0dXJl",
          },
          Session: "Session",
        }),
      ).rejects.toEqual(
        new NotAuthorizedError("Incorrect username or password."),
      );
    });

    it("returns NEW_PASSWORD_REQUIRED after a correct temporary password", async () => {
      const temporary = TDB.user({
        Password: "Temp-Passw0rd!",
        UserStatus: "FORCE_CHANGE_PASSWORD",
      });
      mockUserPoolService.getUserByUsername.mockResolvedValue(temporary);

      const output = await respondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        ChallengeName: "PASSWORD_VERIFIER",
        ChallengeResponses: passwordVerifier("Temp-Passw0rd!", temporary),
        Session: "Session",
      });

      expect(output.ChallengeName).toEqual("NEW_PASSWORD_REQUIRED");
    });
  });
});
