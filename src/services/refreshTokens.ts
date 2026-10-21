import { type AppClient, refreshTokenRotationEnabled } from "./appClient";
import type { Clock } from "./clock";
import type { Context } from "./context";
import type { TokenGenerator, Tokens } from "./tokenGenerator";
import {
  isTokenOriginActive,
  withRefreshTokenRotated,
  withTokenOrigin,
} from "./tokenRevocation";
import type { VerifiedRefreshToken } from "./tokenVerifier";

export interface RefreshedTokens extends VerifiedRefreshToken {
  tokens: Tokens;
  scopes: string[];
  /** The new refresh token when the client rotates them, else undefined. */
  refreshToken: string | undefined;
}

/** Issues access and ID tokens in the same session (origin_jti), and a new refresh token under rotation. */
export const refreshTokens = async (
  ctx: Context,
  services: { clock: Clock; tokenGenerator: TokenGenerator },
  client: AppClient,
  verified: VerifiedRefreshToken,
  clientMetadata?: Record<string, string>,
): Promise<RefreshedTokens> => {
  const { claims, userPool } = verified;
  let { user } = verified;

  const now = services.clock.get();
  const originJti = typeof claims.jti === "string" ? claims.jti : undefined;
  if (originJti && !isTokenOriginActive(user, originJti, now)) {
    const origin = {
      Jti: originJti,
      ClientId: client.ClientId,
      ExpiresAt:
        typeof claims.exp === "number"
          ? claims.exp
          : Math.floor(now.getTime() / 1000),
    };
    user = await userPool.updateUser(ctx, user, (latest) =>
      withTokenOrigin(latest, origin, now),
    );
  }

  const scopes =
    typeof claims.scope === "string"
      ? claims.scope.split(" ").filter(Boolean)
      : [];
  const rotate = refreshTokenRotationEnabled(client);
  const userGroups = await userPool.listUserGroupMembership(ctx, user);
  const tokens = await services.tokenGenerator.generate(
    ctx,
    user,
    userGroups,
    client,
    clientMetadata,
    "RefreshTokens",
    scopes,
    {
      originJti,
      ...(typeof claims.device_key === "string"
        ? { deviceKey: claims.device_key }
        : {}),
      ...(rotate && typeof claims.exp === "number"
        ? { refreshTokenExpiresAt: claims.exp }
        : {}),
    },
  );

  if (rotate) {
    const grace = client.RefreshTokenRotation?.RetryGracePeriodSeconds ?? 0;
    user = await userPool.updateUser(ctx, user, (latest) =>
      withRefreshTokenRotated(
        latest,
        verified.token,
        tokens.RefreshToken,
        services.clock.get(),
        grace,
      ),
    );
  }

  return {
    token: verified.token,
    claims,
    user,
    userPool,
    tokens,
    scopes,
    refreshToken: rotate ? tokens.RefreshToken : undefined,
  };
};
