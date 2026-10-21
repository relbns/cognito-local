import type {
  GetTokensFromRefreshTokenRequest,
  GetTokensFromRefreshTokenResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { NotAuthorizedError } from "../errors";
import type { Services } from "../services";
import { refreshTokens } from "../services/refreshTokens";
import type { Target } from "./Target";

export type GetTokensFromRefreshTokenTarget = Target<
  GetTokensFromRefreshTokenRequest,
  GetTokensFromRefreshTokenResponse
>;

type GetTokensFromRefreshTokenServices = Pick<
  Services,
  "clock" | "cognito" | "tokenGenerator" | "tokenVerifier"
>;

export const GetTokensFromRefreshToken =
  (
    services: GetTokensFromRefreshTokenServices,
  ): GetTokensFromRefreshTokenTarget =>
  async (ctx, req) => {
    const client = await services.cognito.getAppClient(ctx, req.ClientId);
    if (!client) {
      throw new NotAuthorizedError();
    }
    services.tokenVerifier.verifyClientSecret(client, req.ClientSecret);

    const verified = await services.tokenVerifier.verifyRefreshToken(
      ctx,
      req.RefreshToken,
      req.ClientId,
    );
    const { tokens, refreshToken } = await refreshTokens(
      ctx,
      services,
      client,
      verified,
      req.ClientMetadata,
    );

    return {
      AuthenticationResult: {
        AccessToken: tokens.AccessToken,
        IdToken: tokens.IdToken,
        ...(refreshToken ? { RefreshToken: refreshToken } : {}),
        ExpiresIn: tokens.ExpiresIn,
        TokenType: tokens.TokenType,
      },
    };
  };
