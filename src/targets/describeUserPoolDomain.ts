import type {
  DescribeUserPoolDomainRequest,
  DescribeUserPoolDomainResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import type { Target } from "./Target";

export type DescribeUserPoolDomainTarget = Target<
  DescribeUserPoolDomainRequest,
  DescribeUserPoolDomainResponse
>;

type DescribeUserPoolDomainServices = Pick<Services, "cognito">;

export const DescribeUserPoolDomain =
  ({ cognito }: DescribeUserPoolDomainServices): DescribeUserPoolDomainTarget =>
  async (ctx, req) => {
    const userPools = await cognito.listUserPools(ctx);
    const pool = userPools.find((p) => p.Domain === req.Domain);

    if (!pool) {
      return {
        DomainDescription: {},
      };
    }

    return {
      DomainDescription: {
        Domain: req.Domain,
        UserPoolId: pool.Id,
        Status: "ACTIVE",
      },
    };
  };
