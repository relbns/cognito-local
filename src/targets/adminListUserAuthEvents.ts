import type {
  AdminListUserAuthEventsRequest,
  AdminListUserAuthEventsResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import type { Target } from "./Target";

export type AdminListUserAuthEventsTarget = Target<
  AdminListUserAuthEventsRequest,
  AdminListUserAuthEventsResponse
>;

export const AdminListUserAuthEvents =
  ({ cognito }: Pick<Services, "cognito">): AdminListUserAuthEventsTarget =>
  async (ctx, req) => {
    // Ensure pool exists
    await cognito.getUserPool(ctx, req.UserPoolId);

    // Emulator does not track auth events; return empty list
    return {
      AuthEvents: [],
      NextToken: undefined,
    };
  };
