import jwt from "jsonwebtoken";
import * as uuid from "uuid";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newDecodingTokenVerifier } from "../__tests__/mockTokenVerifier";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { NotAuthorizedError, UserNotFoundError } from "../errors";
import PrivateKey from "../keys/cognitoLocal.private.json";
import type { CognitoService, UserPoolService } from "../services";
import { attributeValue } from "../services/userPoolService";
import { GetUser, type GetUserTarget } from "./getUser";

describe("GetUser target", () => {
  let getUser: GetUserTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockCognitoService: MockedObject<CognitoService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockCognitoService.getAppClient.mockResolvedValue(TDB.appClient());
    getUser = GetUser({
      cognito: mockCognitoService,
      tokenVerifier: newDecodingTokenVerifier(mockUserPoolService),
    });
  });

  const accessToken = (user: ReturnType<typeof TDB.user>) =>
    jwt.sign(
      {
        sub: attributeValue("sub", user.Attributes),
        token_use: "access",
        scope: "aws.cognito.signin.user.admin",
        client_id: "test",
        username: user.Username,
      },
      PrivateKey.pem,
      { algorithm: "RS256", expiresIn: "24h", keyid: "CognitoLocal" },
    );

  it("returns only the attributes the client can read, and sub", async () => {
    const user = TDB.user({
      Attributes: [
        { Name: "sub", Value: "user-sub" },
        { Name: "email", Value: "jane@example.test" },
        { Name: "phone_number", Value: "+15555550100" },
        { Name: "custom:tier", Value: "gold" },
      ],
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    mockCognitoService.getAppClient.mockResolvedValue(
      TDB.appClient({ ReadAttributes: ["email", "custom:tier"] }),
    );

    const output = await getUser(TestContext, {
      AccessToken: accessToken(user),
    });

    expect(mockCognitoService.getAppClient).toHaveBeenCalledWith(
      TestContext,
      "test",
    );
    expect(output.UserAttributes).toEqual([
      { Name: "sub", Value: "user-sub" },
      { Name: "email", Value: "jane@example.test" },
      { Name: "custom:tier", Value: "gold" },
    ]);
  });

  it("parses token get user by sub", async () => {
    const user = TDB.user();

    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    const output = await getUser(TestContext, {
      AccessToken: jwt.sign(
        {
          sub: attributeValue("sub", user.Attributes),
          event_id: "0",
          token_use: "access",
          scope: "aws.cognito.signin.user.admin",
          auth_time: new Date(),
          jti: uuid.v4(),
          client_id: "test",
          username: user.Username,
        },
        PrivateKey.pem,
        {
          algorithm: "RS256",
          issuer: `http://localhost:9229/test`,
          expiresIn: "24h",
          keyid: "CognitoLocal",
        },
      ),
    });

    expect(output).toBeDefined();
    expect(output).toEqual({
      UserAttributes: user.Attributes,
      Username: user.Username,
    });
  });

  it("throws if token isn't valid", async () => {
    await expect(
      getUser(TestContext, {
        AccessToken: "blah",
      }),
    ).rejects.toEqual(new NotAuthorizedError("Invalid Access Token"));
  });

  it("throws if user doesn't exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      getUser(TestContext, {
        AccessToken: jwt.sign(
          {
            sub: "0000-0000",
            event_id: "0",
            token_use: "access",
            scope: "aws.cognito.signin.user.admin",
            auth_time: new Date(),
            jti: uuid.v4(),
            client_id: "test",
            username: "0000-0000",
          },
          PrivateKey.pem,
          {
            algorithm: "RS256",
            issuer: `http://localhost:9229/test`,
            expiresIn: "24h",
            keyid: "CognitoLocal",
          },
        ),
      }),
    ).rejects.toEqual(new UserNotFoundError("User does not exist."));
  });
});
