import type {
  UpdateDeviceStatusRequest,
  UpdateDeviceStatusResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
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

    const devices = user.Devices ?? [];
    const device = devices.find((d) => d.DeviceKey === req.DeviceKey);
    if (!device) {
      throw new ResourceNotFoundError("Device not found.");
    }

    device.DeviceLastModifiedDate = clock.get();
    if (req.DeviceRememberedStatus) {
      device.DeviceAttributes = device.DeviceAttributes ?? [];
      const existing = device.DeviceAttributes.find(
        (a: any) => a.Name === "device_status",
      );
      if (existing) {
        existing.Value = req.DeviceRememberedStatus;
      } else {
        device.DeviceAttributes.push({
          Name: "device_status",
          Value: req.DeviceRememberedStatus,
        });
      }
    }

    await userPool.saveUser(ctx, {
      ...user,
      Devices: devices,
      UserLastModifiedDate: clock.get(),
    });

    return {};
  };
