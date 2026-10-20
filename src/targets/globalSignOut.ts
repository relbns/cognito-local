import type {
  GlobalSignOutRequest,
  GlobalSignOutResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { withAllTokensRevoked } from "../services/tokenRevocation";
import type { Target } from "./Target";

export type GlobalSignOutTarget = Target<
  GlobalSignOutRequest,
  GlobalSignOutResponse
>;

type GlobalSignOutServices = Pick<Services, "clock" | "tokenVerifier">;

export const GlobalSignOut =
  ({ clock, tokenVerifier }: GlobalSignOutServices): GlobalSignOutTarget =>
  async (ctx, req) => {
    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    await userPool.updateUser(ctx, user, (latest) => ({
      ...withAllTokensRevoked(latest),
      UserLastModifiedDate: clock.get(),
    }));

    return {};
  };
