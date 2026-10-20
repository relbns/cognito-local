import type {
  RevokeTokenRequest,
  RevokeTokenResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import jwt from "jsonwebtoken";
import {
  NotAuthorizedError,
  UnsupportedOperationError,
  UnsupportedTokenTypeError,
} from "../errors";
import type { Services } from "../services";
import { withRefreshTokenRevoked } from "../services/tokenRevocation";
import type { Target } from "./Target";

export type RevokeTokenTarget = Target<RevokeTokenRequest, RevokeTokenResponse>;

type RevokeTokenServices = Pick<Services, "cognito" | "tokenVerifier">;

export const RevokeToken =
  ({ cognito, tokenVerifier }: RevokeTokenServices): RevokeTokenTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPoolForClientId(ctx, req.ClientId);
    const client = await cognito.getAppClient(ctx, req.ClientId);
    if (!client) {
      throw new NotAuthorizedError();
    }
    tokenVerifier.verifyClientSecret(client, req.ClientSecret);
    if (client.EnableTokenRevocation === false) {
      throw new UnsupportedOperationError(
        "Token revocation is not enabled for this client.",
      );
    }

    const decoded = jwt.decode(req.Token);
    if (decoded && typeof decoded === "object" && decoded.token_use) {
      throw new UnsupportedTokenTypeError();
    }

    const user = await userPool.getUserByRefreshToken(ctx, req.Token);
    if (!user) {
      throw new NotAuthorizedError();
    }
    if (
      decoded &&
      typeof decoded === "object" &&
      decoded.client_id !== undefined &&
      decoded.client_id !== req.ClientId
    ) {
      throw new NotAuthorizedError();
    }

    await userPool.saveUser(ctx, withRefreshTokenRevoked(user, req.Token));

    return {};
  };
