import type {
  AdminGetDeviceRequest,
  AdminGetDeviceResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { UserNotFoundError } from "../errors";
import type { Services } from "../services";
import { requireConfirmedDevice, toDeviceType } from "../services/devices";
import type { Target } from "./Target";

export type AdminGetDeviceTarget = Target<
  AdminGetDeviceRequest,
  AdminGetDeviceResponse
>;

type AdminGetDeviceServices = Pick<Services, "cognito">;

export const AdminGetDevice =
  ({ cognito }: AdminGetDeviceServices): AdminGetDeviceTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) {
      throw new UserNotFoundError("User does not exist.");
    }

    return {
      Device: toDeviceType(requireConfirmedDevice(user, req.DeviceKey)),
    };
  };
