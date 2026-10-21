import type {
  AdminListDevicesRequest,
  AdminListDevicesResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { UserNotFoundError } from "../errors";
import type { Services } from "../services";
import { confirmedDevices, toDeviceType } from "../services/devices";
import { paginate } from "../services/pagination";
import type { Target } from "./Target";

export type AdminListDevicesTarget = Target<
  AdminListDevicesRequest,
  AdminListDevicesResponse
>;

type AdminListDevicesServices = Pick<Services, "cognito">;

export const AdminListDevices =
  ({ cognito }: AdminListDevicesServices): AdminListDevicesTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) {
      throw new UserNotFoundError("User does not exist.");
    }

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
