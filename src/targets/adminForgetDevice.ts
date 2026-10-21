import type { AdminForgetDeviceRequest } from "@aws-sdk/client-cognito-identity-provider";
import { UserNotFoundError } from "../errors";
import type { Services } from "../services";
import { withoutDevice } from "../services/devices";
import type { Target } from "./Target";

export type AdminForgetDeviceTarget = Target<AdminForgetDeviceRequest, {}>;

type AdminForgetDeviceServices = Pick<Services, "cognito" | "clock">;

export const AdminForgetDevice =
  ({ cognito, clock }: AdminForgetDeviceServices): AdminForgetDeviceTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) {
      throw new UserNotFoundError("User does not exist.");
    }

    await userPool.updateUser(ctx, user, (latest) => ({
      ...withoutDevice(latest, req.DeviceKey),
      UserLastModifiedDate: clock.get(),
    }));

    return {};
  };
