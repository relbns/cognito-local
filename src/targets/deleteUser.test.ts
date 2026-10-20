import jwt from "jsonwebtoken";
import * as uuid from "uuid";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newDecodingTokenVerifier } from "../__tests__/mockTokenVerifier";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { NotAuthorizedError, UserNotFoundError } from "../errors";
import PrivateKey from "../keys/cognitoLocal.private.json";
import type { UserPoolService } from "../services";
import { DeleteUser, type DeleteUserTarget } from "./deleteUser";

describe("DeleteUser target", () => {
  let deleteUser: DeleteUserTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    deleteUser = DeleteUser({
      tokenVerifier: newDecodingTokenVerifier(mockUserPoolService),
    });
  });

  it("parses token get user by sub", async () => {
    const user = TDB.user();

    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await deleteUser(TestContext, {
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
    });

    expect(mockUserPoolService.deleteUser).toHaveBeenCalledWith(
      TestContext,
      user,
    );
  });

  it("throws if token isn't valid", async () => {
    await expect(
      deleteUser(TestContext, {
        AccessToken: "blah",
      }),
    ).rejects.toEqual(new NotAuthorizedError("Invalid Access Token"));
  });

  it("throws if user doesn't exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      deleteUser(TestContext, {
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
