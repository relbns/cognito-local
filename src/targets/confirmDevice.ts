import type {
  ConfirmDeviceRequest,
  ConfirmDeviceResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import type { Target } from "./Target";

export type ConfirmDeviceTarget = Target<
  ConfirmDeviceRequest,
  ConfirmDeviceResponse
>;

type ConfirmDeviceServices = Pick<Services, "clock" | "tokenVerifier">;

export const ConfirmDevice =
  ({ clock, tokenVerifier }: ConfirmDeviceServices): ConfirmDeviceTarget =>
  async (ctx, req) => {
    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    const now = clock.get();
    const device = {
      DeviceKey: req.DeviceKey,
      DeviceAttributes: [{ Name: "device_name", Value: req.DeviceName }],
      DeviceCreateDate: now,
      DeviceLastModifiedDate: now,
      DeviceLastAuthenticatedDate: now,
    };

    const devices = user.Devices ?? [];
    devices.push(device);

    await userPool.saveUser(ctx, {
      ...user,
      Devices: devices,
      UserLastModifiedDate: now,
    });

    return {
      UserConfirmationNecessary: false,
    };
  };
