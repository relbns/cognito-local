import jwt from "jsonwebtoken";
import * as uuid from "uuid";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newDecodingTokenVerifier } from "../__tests__/mockTokenVerifier";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError } from "../errors";
import PrivateKey from "../keys/cognitoLocal.private.json";
import { InMemoryAuthSessions, type UserPoolService } from "../services";
import {
  AssociateSoftwareToken,
  type AssociateSoftwareTokenTarget,
} from "./associateSoftwareToken";

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

describe("AssociateSoftwareToken target", () => {
  let associateSoftwareToken: AssociateSoftwareTokenTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let clock: ClockFake;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    clock = new ClockFake(new Date());
    associateSoftwareToken = AssociateSoftwareToken({
      authSessions: new InMemoryAuthSessions(clock),
      cognito: newMockCognitoService(mockUserPoolService),
      tokenVerifier: newDecodingTokenVerifier(mockUserPoolService),
    });
  });

  it("rejects when neither AccessToken nor Session provided", async () => {
    await expect(
      associateSoftwareToken(TestContext, {}),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });

  it("generates and stores a TOTP secret for the authed user", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    const result = await associateSoftwareToken(TestContext, {
      AccessToken: signAccessToken(user.Username),
    });

    expect(result.SecretCode).toMatch(/^[A-Z2-7]+=*$/);
    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        Username: user.Username,
        SoftwareTokenMfaConfiguration: {
          Secret: result.SecretCode,
          Verified: false,
        },
      }),
    );
  });
});
