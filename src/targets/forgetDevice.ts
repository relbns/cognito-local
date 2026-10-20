import type { ForgetDeviceRequest } from "@aws-sdk/client-cognito-identity-provider";
import { ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
import type { Target } from "./Target";

export type ForgetDeviceTarget = Target<ForgetDeviceRequest, {}>;

type ForgetDeviceServices = Pick<Services, "clock" | "tokenVerifier">;

export const ForgetDevice =
  ({ clock, tokenVerifier }: ForgetDeviceServices): ForgetDeviceTarget =>
  async (ctx, req) => {
    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    const devices = user.Devices ?? [];
    const index = devices.findIndex((d) => d.DeviceKey === req.DeviceKey);
    if (index === -1) {
      throw new ResourceNotFoundError("Device not found.");
    }

    devices.splice(index, 1);

    await userPool.saveUser(ctx, {
      ...user,
      Devices: devices,
      UserLastModifiedDate: clock.get(),
    });

    return {};
  };
