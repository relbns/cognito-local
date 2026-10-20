import jwt from "jsonwebtoken";
import { type MockedObject, vi } from "vitest";
import {
  NotAuthorizedError,
  TokenErrorMessages,
  UserNotFoundError,
} from "../errors";
import type { UserPoolService } from "../services";
import type {
  AccessTokenClaims,
  TokenVerifier,
} from "../services/tokenVerifier";

export const newMockTokenVerifier = (): MockedObject<TokenVerifier> => ({
  verifyAccessToken: vi.fn(),
  verifyClientSecret: vi.fn(),
  verifyRefreshToken: vi.fn(),
  verifySecretHash: vi.fn(),
});

/**
 * A verifier for target tests: decodes the token and loads its user from the mocked pool.
 * Signature, expiry and revocation are covered by JwtTokenVerifier's own tests.
 */
export const newDecodingTokenVerifier = (
  userPool: UserPoolService,
): MockedObject<TokenVerifier> => {
  const verifier = newMockTokenVerifier();
  verifier.verifyAccessToken.mockImplementation(async (ctx, token) => {
    const claims = token ? (jwt.decode(token) as AccessTokenClaims) : null;
    if (!claims) {
      throw new NotAuthorizedError(TokenErrorMessages.invalidAccessToken);
    }
    const user = await userPool.getUserByUsername(ctx, claims.sub);
    if (!user) {
      throw new UserNotFoundError(TokenErrorMessages.userDoesNotExist);
    }
    return { claims, user, userPool };
  });
  return verifier;
};
