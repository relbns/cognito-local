import type {
  ListUserImportJobsRequest,
  ListUserImportJobsResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { paginate } from "../services/pagination";
import { importJobsOf, toUserImportJob } from "../services/userImport";
import type { Target } from "./Target";

export type ListUserImportJobsTarget = Target<
  ListUserImportJobsRequest,
  ListUserImportJobsResponse
>;

export const ListUserImportJobs =
  ({ cognito }: Pick<Services, "cognito">): ListUserImportJobsTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const jobs = importJobsOf(userPool.options).map(toUserImportJob);

    const { items, nextToken } = paginate(
      jobs,
      req.MaxResults,
      req.PaginationToken,
    );

    return {
      UserImportJobs: items,
      PaginationToken: nextToken,
    };
  };
