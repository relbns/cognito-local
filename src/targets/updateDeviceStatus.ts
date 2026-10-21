import type {
  UpdateDeviceStatusRequest,
  UpdateDeviceStatusResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { withRememberedStatus } from "../services/devices";
import type { Target } from "./Target";

export type UpdateDeviceStatusTarget = Target<
  UpdateDeviceStatusRequest,
  UpdateDeviceStatusResponse
>;

type UpdateDeviceStatusServices = Pick<Services, "clock" | "tokenVerifier">;

export const UpdateDeviceStatus =
  ({
    clock,
    tokenVerifier,
  }: UpdateDeviceStatusServices): UpdateDeviceStatusTarget =>
  async (ctx, req) => {
    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

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
