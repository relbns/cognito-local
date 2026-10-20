import jwt from "jsonwebtoken";
import type { TokenOrigin, User } from "./userPoolService";

// Access tokens live at most a day, so an origin is kept that long past its refresh token.
const MAX_ACCESS_TOKEN_LIFETIME_SECONDS = 24 * 60 * 60;

export const epochSeconds = (date: Date): number =>
  Math.floor(date.getTime() / 1000);

const isLive = (origin: TokenOrigin, nowSeconds: number): boolean =>
  origin.ExpiresAt + MAX_ACCESS_TOKEN_LIFETIME_SECONDS > nowSeconds;

export const isTokenOriginActive = (
  user: User,
  originJti: string | undefined,
  now: Date,
): boolean =>
  !!originJti &&
  (user.TokenOrigins ?? []).some(
    (origin) => origin.Jti === originJti && isLive(origin, epochSeconds(now)),
  );

export const withTokenOrigin = (
  user: User,
  origin: TokenOrigin,
  now: Date,
): User => {
  const nowSeconds = epochSeconds(now);
  const others = (user.TokenOrigins ?? []).filter(
    (o) => o.Jti !== origin.Jti && isLive(o, nowSeconds),
  );
  const existing = user.TokenOrigins?.find((o) => o.Jti === origin.Jti);
  return {
    ...user,
    TokenOrigins: [
      ...others,
      {
        ...origin,
        ExpiresAt: Math.max(origin.ExpiresAt, existing?.ExpiresAt ?? 0),
      },
    ],
  };
};

const refreshTokenExpired = (refreshToken: string, nowSeconds: number) => {
  const decoded = jwt.decode(refreshToken);
  return (
    !!decoded &&
    typeof decoded === "object" &&
    typeof decoded.exp === "number" &&
    decoded.exp <= nowSeconds
  );
};

export const withRefreshToken = (
  user: User,
  refreshToken: string,
  now: Date,
): User => {
  const nowSeconds = epochSeconds(now);
  const live = (user.RefreshTokens ?? []).filter(
    (token) => !refreshTokenExpired(token, nowSeconds),
  );
  const decoded = jwt.decode(refreshToken);
  const withToken: User = { ...user, RefreshTokens: [...live, refreshToken] };
  if (
    !decoded ||
    typeof decoded !== "object" ||
    typeof decoded.jti !== "string" ||
    typeof decoded.exp !== "number"
  ) {
    return withToken;
  }
  return withTokenOrigin(
    withToken,
    {
      Jti: decoded.jti,
      ClientId: typeof decoded.client_id === "string" ? decoded.client_id : "",
      ExpiresAt: decoded.exp,
    },
    now,
  );
};

export const withAllTokensRevoked = (user: User): User => ({
  ...user,
  RefreshTokens: [],
  TokenOrigins: [],
});

export const withRefreshTokenRevoked = (
  user: User,
  refreshToken: string,
): User => {
  const decoded = jwt.decode(refreshToken);
  const originJti =
    decoded && typeof decoded === "object" && typeof decoded.jti === "string"
      ? decoded.jti
      : undefined;
  return {
    ...user,
    RefreshTokens: (user.RefreshTokens ?? []).filter((t) => t !== refreshToken),
    TokenOrigins: (user.TokenOrigins ?? []).filter((o) => o.Jti !== originJti),
  };
};
