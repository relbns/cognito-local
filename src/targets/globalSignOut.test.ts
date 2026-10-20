import jwt from "jsonwebtoken";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newDecodingTokenVerifier } from "../__tests__/mockTokenVerifier";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { NotAuthorizedError, UserNotFoundError } from "../errors";
import PrivateKey from "../keys/cognitoLocal.private.json";
import type { UserPoolService } from "../services";
import { GlobalSignOut, type GlobalSignOutTarget } from "./globalSignOut";

const currentDate = new Date();

describe("GlobalSignOut target", () => {
  let globalSignOut: GlobalSignOutTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    globalSignOut = GlobalSignOut({
      tokenVerifier: newDecodingTokenVerifier(mockUserPoolService),
      clock: new ClockFake(currentDate),
    });
  });

  it("revokes every refresh and access token for a valid user", async () => {
    const user = TDB.user({
      RefreshTokens: ["token1", "token2"],
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    const validToken = jwt.sign(
      {
        sub: user.Username,
        client_id: "test",
        token_use: "access",
        username: user.Username,
      },
      PrivateKey.pem,
      { algorithm: "RS256", keyid: "CognitoLocal" },
    );

    const result = await globalSignOut(TestContext, {
      AccessToken: validToken,
    });

    expect(result).toEqual({});
    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
      ...user,
      RefreshTokens: [],
      TokenOrigins: [],
      UserLastModifiedDate: currentDate,
    });
  });

  it("throws if token is invalid", async () => {
    await expect(
      globalSignOut(TestContext, { AccessToken: "invalid-token" }),
    ).rejects.toEqual(new NotAuthorizedError("Invalid Access Token"));

    expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
  });

  it("throws if user not found", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    const validToken = jwt.sign(
      {
        sub: "unknown-user",
        client_id: "test",
        token_use: "access",
        username: "unknown-user",
      },
      PrivateKey.pem,
      { algorithm: "RS256", keyid: "CognitoLocal" },
    );

    await expect(
      globalSignOut(TestContext, { AccessToken: validToken }),
    ).rejects.toEqual(new UserNotFoundError("User does not exist."));

    expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
  });
});
