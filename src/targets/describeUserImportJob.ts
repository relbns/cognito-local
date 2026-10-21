import type {
  DescribeUserImportJobRequest,
  DescribeUserImportJobResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
import { importJobsOf, toUserImportJob } from "../services/userImport";
import type { Target } from "./Target";

export type DescribeUserImportJobTarget = Target<
  DescribeUserImportJobRequest,
  DescribeUserImportJobResponse
>;

export const DescribeUserImportJob =
  ({ cognito }: Pick<Services, "cognito">): DescribeUserImportJobTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const job = importJobsOf(userPool.options).find(
      (j) => j.JobId === req.JobId,
    );
    if (!job) {
      throw new ResourceNotFoundError("User import job not found");
    }

    return { UserImportJob: toUserImportJob(job) };
  };
