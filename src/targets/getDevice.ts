import type {
  GetDeviceRequest,
  GetDeviceResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
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

    const devices = user.Devices ?? [];
    const device = devices.find((d) => d.DeviceKey === req.DeviceKey);
    if (!device) {
      throw new ResourceNotFoundError("Device not found.");
    }

    return {
      Device: device,
    };
  };
