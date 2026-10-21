import type { ForgetDeviceRequest } from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { withoutDevice } from "../services/devices";
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

    await userPool.updateUser(ctx, user, (latest) => ({
      ...withoutDevice(latest, req.DeviceKey),
      UserLastModifiedDate: clock.get(),
    }));

    return {};
  };
