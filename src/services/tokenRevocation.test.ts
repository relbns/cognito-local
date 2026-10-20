import jwt from "jsonwebtoken";
import { describe, expect, it } from "vitest";
import * as TDB from "../__tests__/testDataBuilder";
import PrivateKey from "../keys/cognitoLocal.private.json";
import {
  isTokenOriginActive,
  withAllTokensRevoked,
  withRefreshToken,
  withRefreshTokenRevoked,
  withTokenOrigin,
} from "./tokenRevocation";

const now = new Date(2026, 0, 1);
const nowSeconds = Math.floor(now.getTime() / 1000);
const DAY = 24 * 60 * 60;

const refreshToken = (jti: string, exp: number) =>
  jwt.sign(
    { "cognito:username": "u", client_id: "c", jti, exp },
    PrivateKey.pem,
    { algorithm: "RS256" },
  );

describe("token revocation", () => {
  it("registers a refresh token's session and drops expired refresh tokens", () => {
    const expired = refreshToken("old", nowSeconds - 1);
    const fresh = refreshToken("new", nowSeconds + DAY);

    const user = withRefreshToken(
      TDB.user({ RefreshTokens: [expired] }),
      fresh,
      now,
    );

    expect(user.RefreshTokens).toEqual([fresh]);
    expect(user.TokenOrigins).toEqual([
      { Jti: "new", ClientId: "c", ExpiresAt: nowSeconds + DAY },
    ]);
    expect(isTokenOriginActive(user, "new", now)).toBe(true);
    expect(isTokenOriginActive(user, "old", now)).toBe(false);
    expect(isTokenOriginActive(user, undefined, now)).toBe(false);
  });

  it("keeps a session a day past its refresh token, the longest access token life", () => {
    const user = withTokenOrigin(
      TDB.user(),
      { Jti: "s", ClientId: "c", ExpiresAt: nowSeconds },
      now,
    );
    const later = (seconds: number) => new Date(now.getTime() + seconds * 1000);

    expect(isTokenOriginActive(user, "s", later(DAY - 1))).toBe(true);
    expect(isTokenOriginActive(user, "s", later(DAY))).toBe(false);
  });

  it("extends rather than shortens an existing session", () => {
    const origin = { Jti: "s", ClientId: "c", ExpiresAt: nowSeconds + DAY };
    const user = withTokenOrigin(
      withTokenOrigin(TDB.user(), origin, now),
      { ...origin, ExpiresAt: nowSeconds },
      now,
    );

    expect(user.TokenOrigins).toEqual([origin]);
  });

  it("revokes one refresh token and its session", () => {
    const a = refreshToken("a", nowSeconds + DAY);
    const b = refreshToken("b", nowSeconds + DAY);
    const user = withRefreshToken(withRefreshToken(TDB.user(), a, now), b, now);

    const revoked = withRefreshTokenRevoked(user, a);

    expect(revoked.RefreshTokens).toEqual([b]);
    expect(revoked.TokenOrigins?.map((o) => o.Jti)).toEqual(["b"]);
  });

  it("revokes everything", () => {
    const user = withRefreshToken(
      TDB.user(),
      refreshToken("a", nowSeconds + DAY),
      now,
    );

    expect(withAllTokensRevoked(user)).toMatchObject({
      RefreshTokens: [],
      TokenOrigins: [],
    });
  });
});
