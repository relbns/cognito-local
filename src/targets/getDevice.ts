import type {
  GetDeviceRequest,
  GetDeviceResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { requireConfirmedDevice, toDeviceType } from "../services/devices";
import type { Target } from "./Target";

export type GetDeviceTarget = Target<GetDeviceRequest, GetDeviceResponse>;

type GetDeviceServices = Pick<Services, "tokenVerifier">;

export const GetDevice =
  ({ tokenVerifier }: GetDeviceServices): GetDeviceTarget =>
  async (ctx, req) => {
    const { user } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    return {
      Device: toDeviceType(requireConfirmedDevice(user, req.DeviceKey)),
    };
  };
