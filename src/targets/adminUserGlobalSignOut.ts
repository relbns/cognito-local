import type {
  AdminUserGlobalSignOutRequest,
  AdminUserGlobalSignOutResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { UserNotFoundError } from "../errors";
import type { Services } from "../services";
import { withAllTokensRevoked } from "../services/tokenRevocation";
import type { Target } from "./Target";

export type AdminUserGlobalSignOutTarget = Target<
  AdminUserGlobalSignOutRequest,
  AdminUserGlobalSignOutResponse
>;

type AdminUserGlobalSignOutServices = Pick<Services, "cognito" | "clock">;

export const AdminUserGlobalSignOut =
  ({
    cognito,
    clock,
  }: AdminUserGlobalSignOutServices): AdminUserGlobalSignOutTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) {
      throw new UserNotFoundError();
    }

    await userPool.saveUser(ctx, {
      ...withAllTokensRevoked(user),
      UserLastModifiedDate: clock.get(),
    });

    return {};
  };
