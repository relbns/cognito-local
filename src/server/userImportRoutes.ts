import { timingSafeEqual } from "node:crypto";
import bodyParser from "body-parser";
import type { Application, Request, Response } from "express";
import { ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
import {
  importJobsOf,
  saveImportJobs,
  USER_IMPORT_MAX_BYTES,
  USER_IMPORT_PATH,
} from "../services/userImport";

const s3Error = (
  res: Response,
  status: number,
  code: string,
  message: string,
) =>
  res
    .status(status)
    .type("application/xml")
    .send(
      `<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>${code}</Code><Message>${message}</Message></Error>`,
    );

const sameToken = (given: unknown, expected: string | undefined): boolean =>
  typeof given === "string" &&
  !!expected &&
  given.length === expected.length &&
  timingSafeEqual(Buffer.from(given), Buffer.from(expected));

/** Serves the PreSignedUrl of CreateUserImportJob: a PUT stores the CSV on the job. */
export const attachUserImportRoutes = (
  app: Application,
  services: Services,
) => {
  app.put(
    `${USER_IMPORT_PATH}/:userPoolId/:jobId`,
    bodyParser.raw({ type: () => true, limit: USER_IMPORT_MAX_BYTES }),
    async (req: Request, res: Response) => {
      const ctx = { logger: req.log };
      try {
        const userPool = await services.cognito.getUserPool(
          ctx,
          req.params.userPoolId,
        );
        const jobs = importJobsOf(userPool.options);
        const job = jobs.find((j) => j.JobId === req.params.jobId);
        if (
          !job ||
          !sameToken(req.query["X-Amz-Signature"], job._uploadToken)
        ) {
          s3Error(
            res,
            403,
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided.",
          );
          return;
        }
        if (job.Status !== "Created") {
          s3Error(
            res,
            403,
            "AccessDenied",
            `The user import job is ${job.Status}; upload the CSV before StartUserImportJob.`,
          );
          return;
        }
        const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
        job._csv = body.toString("utf8");
        await saveImportJobs(ctx, userPool, jobs);
        res.status(200).set("ETag", `"${job.JobId}"`).end();
      } catch (e) {
        if (e instanceof ResourceNotFoundError) {
          s3Error(res, 404, "NoSuchKey", "The specified key does not exist.");
          return;
        }
        req.log.error(e, "user import upload failed");
        s3Error(res, 500, "InternalError", "We encountered an internal error.");
      }
    },
  );
};
