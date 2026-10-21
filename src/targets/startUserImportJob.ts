import type {
  StartUserImportJobRequest,
  StartUserImportJobResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { InvalidParameterError, ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
import {
  importJobsOf,
  runUserImport,
  saveImportJobs,
  toUserImportJob,
} from "../services/userImport";
import type { Target } from "./Target";

export type StartUserImportJobTarget = Target<
  StartUserImportJobRequest,
  StartUserImportJobResponse
>;

export const StartUserImportJob =
  ({
    cognito,
    clock,
  }: Pick<Services, "cognito" | "clock">): StartUserImportJobTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const jobs = importJobsOf(userPool.options);
    const idx = jobs.findIndex((j) => j.JobId === req.JobId);
    if (idx < 0) {
      throw new ResourceNotFoundError("User import job not found");
    }
    if (jobs[idx].Status !== "Created") {
      throw new InvalidParameterError(
        `User import job ${req.JobId} is ${jobs[idx].Status} and can only be started from Created.`,
      );
    }

    const pending = {
      ...jobs[idx],
      Status: "Pending" as const,
      StartDate: clock.get(),
    };
    const result = await runUserImport(ctx, userPool, clock, pending._csv);
    for (const line of result.log) {
      ctx.logger.warn({ jobId: req.JobId }, line);
    }

    const { _csv, ...rest } = pending;
    jobs[idx] = {
      ...rest,
      Status: result.status,
      CompletionDate: clock.get(),
      CompletionMessage: result.completionMessage,
      ImportedUsers: result.imported,
      FailedUsers: result.failed,
      SkippedUsers: result.skipped,
      _log: result.log,
    };
    await saveImportJobs(ctx, userPool, jobs);

    return { UserImportJob: toUserImportJob(pending) };
  };
