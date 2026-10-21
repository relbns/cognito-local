import type {
  AdminDisableUserRequest,
  AdminDisableUserResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { UserNotFoundError } from "../errors";
import type { Services } from "../services";
import { withAllTokensRevoked } from "../services/tokenRevocation";
import type { Target } from "./Target";

export type AdminDisableUserTarget = Target<
  AdminDisableUserRequest,
  AdminDisableUserResponse
>;

type AdminDisableUserServices = Pick<Services, "cognito" | "clock">;

export const AdminDisableUser =
  ({ cognito, clock }: AdminDisableUserServices): AdminDisableUserTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) {
      throw new UserNotFoundError("User does not exist.");
    }

    await userPool.updateUser(ctx, user, (latest) => ({
      ...withAllTokensRevoked(latest),
      Enabled: false,
      UserLastModifiedDate: clock.get(),
    }));

    return {};
  };
