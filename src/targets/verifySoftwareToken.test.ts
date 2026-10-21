import jwt from "jsonwebtoken";
import * as uuid from "uuid";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newDecodingTokenVerifier } from "../__tests__/mockTokenVerifier";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  EnableSoftwareTokenMFAError,
  InvalidParameterError,
  NotAuthorizedError,
} from "../errors";
import PrivateKey from "../keys/cognitoLocal.private.json";
import { InMemoryAuthSessions, type UserPoolService } from "../services";
import { generate, generateSecret } from "../services/totp";
import { AssociateSoftwareToken } from "./associateSoftwareToken";
import {
  VerifySoftwareToken,
  type VerifySoftwareTokenTarget,
} from "./verifySoftwareToken";

const signAccessToken = (sub: string) =>
  jwt.sign(
    {
      sub,
      event_id: "0",
      token_use: "access",
      scope: "aws.cognito.signin.user.admin",
      auth_time: new Date(),
      jti: uuid.v4(),
      client_id: "test",
      username: sub,
    },
    PrivateKey.pem,
    {
      algorithm: "RS256",
      issuer: "http://localhost:9229/test",
      expiresIn: "24h",
      keyid: "CognitoLocal",
    },
  );

describe("VerifySoftwareToken target", () => {
  let verifySoftwareToken: VerifySoftwareTokenTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let clock: ClockFake;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    clock = new ClockFake(new Date());
    verifySoftwareToken = VerifySoftwareToken({
      authSessions: new InMemoryAuthSessions(clock),
      clock,
      cognito: newMockCognitoService(mockUserPoolService),
      tokenVerifier: newDecodingTokenVerifier(mockUserPoolService),
    });
  });

  it("verifies a correct code and marks the secret verified", async () => {
    const secret = generateSecret();
    const user = TDB.user({
      SoftwareTokenMfaConfiguration: { Secret: secret, Verified: false },
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    const result = await verifySoftwareToken(TestContext, {
      AccessToken: signAccessToken(user.Username),
      UserCode: generate(secret),
      FriendlyDeviceName: "iPhone",
    });

    expect(result.Status).toBe("SUCCESS");
    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        SoftwareTokenMfaConfiguration: {
          Secret: secret,
          Verified: true,
          FriendlyDeviceName: "iPhone",
        },
        UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
      }),
    );
  });

  it("rejects a wrong code", async () => {
    const secret = generateSecret();
    const user = TDB.user({
      SoftwareTokenMfaConfiguration: { Secret: secret, Verified: false },
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      verifySoftwareToken(TestContext, {
        AccessToken: signAccessToken(user.Username),
        UserCode: "000000",
      }),
    ).rejects.toBeInstanceOf(EnableSoftwareTokenMFAError);
    expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
  });

  it("rejects when the user has no associated secret", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      verifySoftwareToken(TestContext, {
        AccessToken: signAccessToken(user.Username),
        UserCode: "123456",
      }),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });

  describe("with the Session of an MFA_SETUP challenge", () => {
    const client = TDB.appClient({ UserPoolId: "test" });
    let authSessions: InMemoryAuthSessions;
    let sessionId: string;
    let user: ReturnType<typeof TDB.user>;

    const services = () => {
      const cognito = newMockCognitoService(mockUserPoolService);
      cognito.getAppClient.mockResolvedValue(client);
      return {
        authSessions,
        clock,
        cognito,
        tokenVerifier: newDecodingTokenVerifier(mockUserPoolService),
      };
    };

    beforeEach(() => {
      authSessions = new InMemoryAuthSessions(clock);
      user = TDB.user();
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      sessionId = authSessions.create({
        userPoolId: "test",
        clientId: client.ClientId,
        username: user.Username,
        history: [],
        pendingChallenge: {
          challengeName: "MFA_SETUP",
          privateChallengeParameters: {},
        },
        signIn: {},
      });
    });

    it("associates a secret, verifies a code and hands back a new Session each time", async () => {
      const associated = await AssociateSoftwareToken(services())(TestContext, {
        Session: sessionId,
      });
      expect(associated.SecretCode).toMatch(/^[A-Z2-7]+=*$/);
      expect(associated.Session).not.toEqual(sessionId);
      expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();

      const verify = VerifySoftwareToken(services());
      await expect(
        verify(TestContext, {
          Session: associated.Session,
          UserCode: "000000",
        }),
      ).rejects.toBeInstanceOf(EnableSoftwareTokenMFAError);

      const verified = await verify(TestContext, {
        Session: associated.Session,
        UserCode: generate(associated.SecretCode as string),
        FriendlyDeviceName: "Phone",
      });
      expect(verified.Status).toEqual("SUCCESS");
      expect(verified.Session).not.toEqual(associated.Session);
      expect(authSessions.peek(verified.Session as string)?.signIn).toEqual({
        totpSecret: associated.SecretCode,
        totpVerified: true,
      });
      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
        TestContext,
        expect.objectContaining({
          SoftwareTokenMfaConfiguration: {
            Secret: associated.SecretCode,
            Verified: true,
            FriendlyDeviceName: "Phone",
          },
          UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
          PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
        }),
      );
    });

    it("refuses a session that is unknown or not waiting for MFA_SETUP", async () => {
      await expect(
        AssociateSoftwareToken(services())(TestContext, {
          Session: "unknown-session-id-0000",
        }),
      ).rejects.toEqual(
        new NotAuthorizedError("Invalid session for the user."),
      );

      const other = authSessions.create({
        userPoolId: "test",
        clientId: client.ClientId,
        username: user.Username,
        history: [],
        pendingChallenge: {
          challengeName: "SMS_MFA",
          privateChallengeParameters: {},
        },
        signIn: {},
      });
      await expect(
        VerifySoftwareToken(services())(TestContext, {
          Session: other,
          UserCode: "123456",
        }),
      ).rejects.toEqual(
        new NotAuthorizedError("Invalid session for the user."),
      );
    });

    it("refuses to verify before a secret was associated", async () => {
      await expect(
        VerifySoftwareToken(services())(TestContext, {
          Session: sessionId,
          UserCode: "123456",
        }),
      ).rejects.toBeInstanceOf(InvalidParameterError);
    });
  });
});
