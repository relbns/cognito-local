import type {
  AdminSetUserPasswordRequest,
  AdminSetUserPasswordResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { UserNotFoundError } from "../errors";
import type { Services } from "../services";
import { assertPasswordConformsToPolicy } from "../services/passwordPolicy";
import type { Target } from "./Target";

export type AdminSetUserPasswordTarget = Target<
  AdminSetUserPasswordRequest,
  AdminSetUserPasswordResponse
>;

type AdminSetUserPasswordServices = Pick<Services, "clock" | "cognito"> &
  Partial<Pick<Services, "config">>;

export const AdminSetUserPassword =
  ({
    cognito,
    clock,
    config,
  }: AdminSetUserPasswordServices): AdminSetUserPasswordTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) {
      throw new UserNotFoundError("User does not exist.");
    }

    assertPasswordConformsToPolicy(config, userPool.options, req.Password);

    await userPool.saveUser(ctx, {
      ...user,
      Password: req.Password,
      UserLastModifiedDate: clock.get(),
      UserStatus: req.Permanent ? "CONFIRMED" : "FORCE_CHANGE_PASSWORD",
    });

    return {};
  };
