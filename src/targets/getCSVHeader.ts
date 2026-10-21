import type {
  GetCSVHeaderRequest,
  GetCSVHeaderResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { csvHeaderFor } from "../services/userImport";
import type { Target } from "./Target";

export type GetCSVHeaderTarget = Target<
  GetCSVHeaderRequest,
  GetCSVHeaderResponse
>;

export const GetCSVHeader =
  ({ cognito }: Pick<Services, "cognito">): GetCSVHeaderTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);

    return {
      UserPoolId: req.UserPoolId,
      CSVHeader: csvHeaderFor(userPool.options),
    };
  };
