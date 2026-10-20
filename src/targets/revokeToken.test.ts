import jwt from "jsonwebtoken";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockTokenVerifier } from "../__tests__/mockTokenVerifier";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  NotAuthorizedError,
  UnsupportedOperationError,
  UnsupportedTokenTypeError,
} from "../errors";
import PrivateKey from "../keys/cognitoLocal.private.json";
import type { CognitoService, UserPoolService } from "../services";
import type { TokenVerifier } from "../services/tokenVerifier";
import { RevokeToken, type RevokeTokenTarget } from "./revokeToken";

const sign = (payload: object) =>
  jwt.sign(payload, PrivateKey.pem, { algorithm: "RS256" });

describe("RevokeToken target", () => {
  let revokeToken: RevokeTokenTarget;

  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockCognitoService: MockedObject<CognitoService>;
  let mockTokenVerifier: MockedObject<TokenVerifier>;
  const client = TDB.appClient({ ClientId: "clientId" });
  const refreshToken = sign({
    "cognito:username": "u",
    client_id: "clientId",
    jti: "origin",
  });

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockCognitoService.getAppClient.mockResolvedValue(client);
    mockTokenVerifier = newMockTokenVerifier();

    revokeToken = RevokeToken({
      cognito: mockCognitoService,
      tokenVerifier: mockTokenVerifier,
    });
  });

  it("revokes the refresh token and the access tokens issued from it", async () => {
    const existingUser = TDB.user({
      RefreshTokens: [refreshToken, "other"],
      TokenOrigins: [
        { Jti: "origin", ClientId: "clientId", ExpiresAt: 4e9 },
        { Jti: "other-origin", ClientId: "clientId", ExpiresAt: 4e9 },
      ],
    });
    mockUserPoolService.getUserByRefreshToken.mockResolvedValue(existingUser);

    await revokeToken(TestContext, {
      ClientId: "clientId",
      Token: refreshToken,
    });

    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
      ...existingUser,
      RefreshTokens: ["other"],
      TokenOrigins: [
        { Jti: "other-origin", ClientId: "clientId", ExpiresAt: 4e9 },
      ],
    });
  });

  it("checks the client secret", async () => {
    mockTokenVerifier.verifyClientSecret.mockImplementation(() => {
      throw new NotAuthorizedError("secret");
    });

    await expect(
      revokeToken(TestContext, { ClientId: "clientId", Token: refreshToken }),
    ).rejects.toEqual(new NotAuthorizedError("secret"));
    expect(mockTokenVerifier.verifyClientSecret).toHaveBeenCalledWith(
      client,
      undefined,
    );
  });

  it("refuses when the client has token revocation disabled", async () => {
    mockCognitoService.getAppClient.mockResolvedValue({
      ...client,
      EnableTokenRevocation: false,
    });

    await expect(
      revokeToken(TestContext, { ClientId: "clientId", Token: refreshToken }),
    ).rejects.toBeInstanceOf(UnsupportedOperationError);
  });

  it("refuses an access token", async () => {
    await expect(
      revokeToken(TestContext, {
        ClientId: "clientId",
        Token: sign({ token_use: "access" }),
      }),
    ).rejects.toBeInstanceOf(UnsupportedTokenTypeError);
  });

  it("refuses a refresh token issued to another client", async () => {
    mockUserPoolService.getUserByRefreshToken.mockResolvedValue(
      TDB.user({ RefreshTokens: [refreshToken] }),
    );

    await expect(
      revokeToken(TestContext, { ClientId: "clientId", Token: refreshToken }),
    ).resolves.toEqual({});
    mockCognitoService.getAppClient.mockResolvedValue({
      ...client,
      ClientId: "another",
    });
    await expect(
      revokeToken(TestContext, { ClientId: "another", Token: refreshToken }),
    ).rejects.toBeInstanceOf(NotAuthorizedError);
  });

  it("throws NotAuthorized for an unknown refresh token", async () => {
    mockUserPoolService.getUserByRefreshToken.mockResolvedValue(null);

    await expect(
      revokeToken(TestContext, { ClientId: "clientId", Token: refreshToken }),
    ).rejects.toBeInstanceOf(NotAuthorizedError);
  });
});
