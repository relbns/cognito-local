import type {
  AdminUpdateDeviceStatusRequest,
  AdminUpdateDeviceStatusResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { UserNotFoundError } from "../errors";
import type { Services } from "../services";
import { withRememberedStatus } from "../services/devices";
import type { Target } from "./Target";

export type AdminUpdateDeviceStatusTarget = Target<
  AdminUpdateDeviceStatusRequest,
  AdminUpdateDeviceStatusResponse
>;

type AdminUpdateDeviceStatusServices = Pick<Services, "cognito" | "clock">;

export const AdminUpdateDeviceStatus =
  ({
    cognito,
    clock,
  }: AdminUpdateDeviceStatusServices): AdminUpdateDeviceStatusTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) {
      throw new UserNotFoundError("User does not exist.");
    }

    const now = clock.get();
    await userPool.updateUser(ctx, user, (latest) => ({
      ...withRememberedStatus(
        latest,
        req.DeviceKey,
        req.DeviceRememberedStatus,
        now,
      ),
      UserLastModifiedDate: now,
    }));

    return {};
  };
