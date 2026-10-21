import { randomBytes } from "node:crypto";
import type {
  CreateUserImportJobRequest,
  CreateUserImportJobResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import * as uuid from "uuid";
import type { Services } from "../services";
import {
  importJobsOf,
  type StoredUserImportJob,
  saveImportJobs,
  toUserImportJob,
  userImportUrl,
} from "../services/userImport";
import type { Target } from "./Target";

export type CreateUserImportJobTarget = Target<
  CreateUserImportJobRequest,
  CreateUserImportJobResponse
>;

export const CreateUserImportJob =
  ({
    cognito,
    clock,
    config,
  }: Pick<
    Services,
    "cognito" | "clock" | "config"
  >): CreateUserImportJobTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const jobId = `import-${uuid.v4().replace(/-/g, "").slice(0, 10)}`;
    const uploadToken = randomBytes(24).toString("hex");

    const job: StoredUserImportJob = {
      JobName: req.JobName,
      JobId: jobId,
      UserPoolId: req.UserPoolId,
      PreSignedUrl: userImportUrl(
        config.TokenConfig.IssuerDomain ?? "http://localhost:9229",
        req.UserPoolId,
        jobId,
        uploadToken,
      ),
      CreationDate: clock.get(),
      Status: "Created",
      CloudWatchLogsRoleArn: req.CloudWatchLogsRoleArn,
      ImportedUsers: 0,
      SkippedUsers: 0,
      FailedUsers: 0,
      _uploadToken: uploadToken,
    };

    await saveImportJobs(ctx, userPool, [
      ...importJobsOf(userPool.options),
      job,
    ]);

    return { UserImportJob: toUserImportJob(job) };
  };
