import type {
  DescribeUserPoolClientRequest,
  DescribeUserPoolClientResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
import { appClientToResponseObject } from "./responses";
import type { Target } from "./Target";

export type DescribeUserPoolClientTarget = Target<
  DescribeUserPoolClientRequest,
  DescribeUserPoolClientResponse
>;

export const DescribeUserPoolClient =
  ({ cognito }: Pick<Services, "cognito">): DescribeUserPoolClientTarget =>
  async (ctx, req) => {
    const client = await cognito.getAppClient(ctx, req.ClientId);
    if (client?.UserPoolId !== req.UserPoolId) {
      throw new ResourceNotFoundError();
    }

    return {
      UserPoolClient: appClientToResponseObject(client),
    };
  };
