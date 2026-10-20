import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTokenVerifier } from "../__tests__/mockTokenVerifier";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { NotAuthorizedError } from "../errors";
import type { CognitoService, UserPoolService } from "../services";
import type { TokenGenerator } from "../services/tokenGenerator";
import type { TokenVerifier } from "../services/tokenVerifier";
import {
  GetTokensFromRefreshToken,
  type GetTokensFromRefreshTokenTarget,
} from "./getTokensFromRefreshToken";

describe("GetTokensFromRefreshToken target", () => {
  let getTokensFromRefreshToken: GetTokensFromRefreshTokenTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockCognitoService: MockedObject<CognitoService>;
  let mockTokenGenerator: MockedObject<TokenGenerator>;
  let mockTokenVerifier: MockedObject<TokenVerifier>;

  const userPoolClient = TDB.appClient({
    ClientId: "test-client",
    AccessTokenValidity: 15,
    TokenValidityUnits: { AccessToken: "minutes" },
  });

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockTokenGenerator = newMockTokenGenerator();
    mockTokenVerifier = newMockTokenVerifier();
    mockCognitoService.getAppClient.mockResolvedValue(userPoolClient);

    getTokensFromRefreshToken = GetTokensFromRefreshToken({
      clock: new ClockFake(new Date()),
      cognito: mockCognitoService,
      tokenGenerator: mockTokenGenerator,
      tokenVerifier: mockTokenVerifier,
    });
  });

  it("generates new tokens from a valid refresh token", async () => {
    const user = TDB.user({
      RefreshTokens: ["valid-refresh-token"],
      TokenOrigins: [
        { Jti: "origin", ClientId: "test-client", ExpiresAt: 4e9 },
      ],
    });
    mockTokenVerifier.verifyRefreshToken.mockResolvedValue({
      claims: { "cognito:username": user.Username, jti: "origin" },
      user,
      userPool: mockUserPoolService,
    });
    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "new-access-token",
      IdToken: "new-id-token",
      RefreshToken: "new-refresh-token",
      ExpiresIn: 900,
      TokenType: "Bearer",
    });

    const result = await getTokensFromRefreshToken(TestContext, {
      RefreshToken: "valid-refresh-token",
      ClientId: "test-client",
      ClientSecret: "secret",
    });

    expect(result.AuthenticationResult).toEqual({
      AccessToken: "new-access-token",
      IdToken: "new-id-token",
      ExpiresIn: 900,
      TokenType: "Bearer",
    });
    expect(mockTokenVerifier.verifyClientSecret).toHaveBeenCalledWith(
      userPoolClient,
      "secret",
    );
    expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
      TestContext,
      user,
      [],
      userPoolClient,
      undefined,
      "RefreshTokens",
      [],
      { originJti: "origin" },
    );
  });

  it("passes on the verifier's error for an unusable refresh token", async () => {
    mockTokenVerifier.verifyRefreshToken.mockRejectedValue(
      new NotAuthorizedError("Refresh Token has expired"),
    );

    await expect(
      getTokensFromRefreshToken(TestContext, {
        RefreshToken: "expired-token",
        ClientId: "test-client",
      }),
    ).rejects.toEqual(new NotAuthorizedError("Refresh Token has expired"));
  });

  it("throws NotAuthorizedError if app client not found", async () => {
    mockCognitoService.getAppClient.mockResolvedValue(null);

    await expect(
      getTokensFromRefreshToken(TestContext, {
        RefreshToken: "some-token",
        ClientId: "unknown-client",
      }),
    ).rejects.toBeInstanceOf(NotAuthorizedError);
  });
});
