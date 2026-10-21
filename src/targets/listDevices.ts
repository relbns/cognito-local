import type {
  ListDevicesRequest,
  ListDevicesResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { confirmedDevices, toDeviceType } from "../services/devices";
import { paginate } from "../services/pagination";
import type { Target } from "./Target";

export type ListDevicesTarget = Target<ListDevicesRequest, ListDevicesResponse>;

type ListDevicesServices = Pick<Services, "tokenVerifier">;

export const ListDevices =
  ({ tokenVerifier }: ListDevicesServices): ListDevicesTarget =>
  async (ctx, req) => {
    const { user } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    const { items, nextToken } = paginate(
      confirmedDevices(user).map(toDeviceType),
      req.Limit,
      req.PaginationToken,
    );

    return {
      Devices: items,
      PaginationToken: nextToken,
    };
  };
