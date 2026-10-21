import type {
  StopUserImportJobRequest,
  StopUserImportJobResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { InvalidParameterError, ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
import {
  importJobsOf,
  saveImportJobs,
  toUserImportJob,
} from "../services/userImport";
import type { Target } from "./Target";

export type StopUserImportJobTarget = Target<
  StopUserImportJobRequest,
  StopUserImportJobResponse
>;

export const StopUserImportJob =
  ({
    cognito,
    clock,
  }: Pick<Services, "cognito" | "clock">): StopUserImportJobTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const jobs = importJobsOf(userPool.options);
    const idx = jobs.findIndex((j) => j.JobId === req.JobId);
    if (idx < 0) {
      throw new ResourceNotFoundError("User import job not found");
    }

    const { _csv, ...job } = jobs[idx];
    if (!["Created", "Pending", "InProgress"].includes(job.Status ?? "")) {
      throw new InvalidParameterError(
        `User import job ${req.JobId} is ${job.Status} and cannot be stopped.`,
      );
    }
    jobs[idx] = { ...job, Status: "Stopped", CompletionDate: clock.get() };

    await saveImportJobs(ctx, userPool, jobs);

    return { UserImportJob: toUserImportJob(jobs[idx]) };
  };
