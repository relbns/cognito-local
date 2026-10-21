import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "./setup";

const HEADER =
  "name,given_name,family_name,middle_name,nickname,preferred_username,profile,picture,website,email,email_verified,gender,birthdate,zoneinfo,locale,phone_number,phone_number_verified,address,updated_at,cognito:mfa_enabled,cognito:username";

const row = (fields: Record<string, string>) =>
  HEADER.split(",")
    .map((name) => fields[name] ?? "")
    .join(",");

describe(
  "user import jobs",
  withCognitoSdk((Cognito, { serverUrl, messageDelivery }) => {
    const setup = async () => {
      const client = Cognito();
      const pool = await client
        .createUserPool({
          PoolName: "import",
          UsernameAttributes: [],
          AutoVerifiedAttributes: ["email"],
        })
        .promise();
      const UserPoolId = pool.UserPool!.Id!;
      const app = await client
        .createUserPoolClient({
          UserPoolId,
          ClientName: "web",
          ExplicitAuthFlows: [
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
          ],
        })
        .promise();
      return { client, UserPoolId, ClientId: app.UserPoolClient!.ClientId! };
    };

    const upload = async (preSignedUrl: string, body: string) => {
      const url = new URL(preSignedUrl);
      return fetch(`${serverUrl()}${url.pathname}${url.search}`, {
        method: "PUT",
        headers: {
          "content-type": "text/csv",
          "x-amz-server-side-encryption": "aws:kms",
        },
        body,
      });
    };

    const createJob = async (
      client: ReturnType<typeof Cognito>,
      UserPoolId: string,
    ) =>
      (
        await client
          .createUserImportJob({
            UserPoolId,
            JobName: "users",
            CloudWatchLogsRoleArn:
              "arn:aws:iam::123456789012:role/CognitoImport",
          })
          .promise()
      ).UserImportJob!;

    it("imports the users of an uploaded CSV as RESET_REQUIRED", async () => {
      const { client, UserPoolId, ClientId } = await setup();

      const header = await client.getCSVHeader({ UserPoolId }).promise();
      expect(header.CSVHeader?.join(",")).toEqual(HEADER);

      const job = await createJob(client, UserPoolId);
      expect(job).toMatchObject({
        JobName: "users",
        Status: "Created",
        ImportedUsers: 0,
      });
      expect(job.JobId).toMatch(/^import-[0-9a-zA-Z-]+$/);
      expect(job.PreSignedUrl).toContain(
        `/_import/${UserPoolId}/${job.JobId}?`,
      );

      const csv = [
        HEADER,
        row({
          "cognito:username": "jane",
          email: "jane@example.com",
          email_verified: "TRUE",
          name: '"Jane, Q"',
          "cognito:mfa_enabled": "FALSE",
        }),
        row({
          "cognito:username": "lee",
          email: "lee@example.com",
          email_verified: "true",
          phone_number: "+15555550100",
          phone_number_verified: "true",
          "cognito:mfa_enabled": "TRUE",
        }),
        row({
          "cognito:username": "noverify",
          email: "nv@example.com",
          email_verified: "FALSE",
          "cognito:mfa_enabled": "FALSE",
        }),
        row({
          "cognito:username": "jane",
          email: "jane2@example.com",
          email_verified: "TRUE",
          "cognito:mfa_enabled": "FALSE",
        }),
        "",
      ].join("\r\n");
      expect((await upload(job.PreSignedUrl!, csv)).status).toBe(200);

      const started = await client
        .startUserImportJob({ UserPoolId, JobId: job.JobId! })
        .promise();
      expect(started.UserImportJob).toMatchObject({ Status: "Pending" });
      expect(started.UserImportJob?.StartDate).toBeInstanceOf(Date);

      const described = await client
        .describeUserImportJob({ UserPoolId, JobId: job.JobId! })
        .promise();
      expect(described.UserImportJob).toMatchObject({
        Status: "Succeeded",
        CompletionMessage: "Import Job Completed Successfully.",
        ImportedUsers: 2,
        FailedUsers: 2,
        SkippedUsers: 0,
      });

      const jane = await client
        .adminGetUser({ UserPoolId, Username: "jane" })
        .promise();
      expect(jane.UserStatus).toBe("RESET_REQUIRED");
      expect(jane.UserAttributes).toEqual(
        expect.arrayContaining([
          { Name: "email", Value: "jane@example.com" },
          { Name: "email_verified", Value: "true" },
          { Name: "name", Value: "Jane, Q" },
          { Name: "sub", Value: expect.any(String) },
        ]),
      );
      const lee = await client
        .adminGetUser({ UserPoolId, Username: "lee" })
        .promise();
      expect(lee.UserMFASettingList).toEqual(["SMS_MFA"]);

      await expect(
        client
          .initiateAuth({
            ClientId,
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: { USERNAME: "jane", PASSWORD: "anything" },
          })
          .promise(),
      ).rejects.toMatchObject({ code: "PasswordResetRequiredException" });

      await client.forgotPassword({ ClientId, Username: "jane" }).promise();
      const code = messageDelivery().collectedMessages.at(-1)?.message.__code;
      await client
        .confirmForgotPassword({
          ClientId,
          Username: "jane",
          ConfirmationCode: code!,
          Password: "NewPassw0rd!",
        })
        .promise();
      const signedIn = await client
        .initiateAuth({
          ClientId,
          AuthFlow: "USER_PASSWORD_AUTH",
          AuthParameters: { USERNAME: "jane", PASSWORD: "NewPassw0rd!" },
        })
        .promise();
      expect(signedIn.AuthenticationResult?.AccessToken).toBeDefined();

      const listed = await client
        .listUserImportJobs({ UserPoolId, MaxResults: 10 })
        .promise();
      expect(listed.UserImportJobs?.map((j) => j.Status)).toEqual([
        "Succeeded",
      ]);
      expect(Object.keys(listed.UserImportJobs![0])).not.toContain("_log");
    });

    it("fails the job when no CSV was uploaded or the header is wrong", async () => {
      const { client, UserPoolId } = await setup();

      const empty = await createJob(client, UserPoolId);
      await client
        .startUserImportJob({ UserPoolId, JobId: empty.JobId! })
        .promise();
      expect(
        (
          await client
            .describeUserImportJob({ UserPoolId, JobId: empty.JobId! })
            .promise()
        ).UserImportJob,
      ).toMatchObject({
        Status: "Failed",
        CompletionMessage:
          "No CSV file was uploaded to the job's PreSignedUrl.",
      });

      const bad = await createJob(client, UserPoolId);
      await upload(
        bad.PreSignedUrl!,
        "email,favourite_colour\na@example.com,red\n",
      );
      await client
        .startUserImportJob({ UserPoolId, JobId: bad.JobId! })
        .promise();
      expect(
        (
          await client
            .describeUserImportJob({ UserPoolId, JobId: bad.JobId! })
            .promise()
        ).UserImportJob,
      ).toMatchObject({
        Status: "Failed",
        CompletionMessage:
          "The CSV header has columns the user pool does not have: favourite_colour.",
      });

      await expect(
        client.startUserImportJob({ UserPoolId, JobId: bad.JobId! }).promise(),
      ).rejects.toMatchObject({ code: "InvalidParameterException" });
    });

    it("stops a job that has not finished, and only once", async () => {
      const { client, UserPoolId } = await setup();
      const job = await createJob(client, UserPoolId);

      const stopped = await client
        .stopUserImportJob({ UserPoolId, JobId: job.JobId! })
        .promise();

      expect(stopped.UserImportJob).toMatchObject({
        JobId: job.JobId,
        Status: "Stopped",
        CompletionDate: expect.any(Date),
      });
      await expect(
        client.stopUserImportJob({ UserPoolId, JobId: job.JobId! }).promise(),
      ).rejects.toMatchObject({
        code: "InvalidParameterException",
        message: `User import job ${job.JobId} is Stopped and cannot be stopped.`,
      });
      await expect(
        client
          .stopUserImportJob({
            UserPoolId,
            JobId: "import-0000000000000000000000",
          })
          .promise(),
      ).rejects.toMatchObject({ code: "ResourceNotFoundException" });
    });

    it("refuses an upload with a wrong signature or after the job started", async () => {
      const { client, UserPoolId } = await setup();
      const job = await createJob(client, UserPoolId);
      const url = new URL(job.PreSignedUrl!);
      url.searchParams.set("X-Amz-Signature", "0".repeat(48));

      const forged = await upload(url.toString(), `${HEADER}\n`);
      expect(forged.status).toBe(403);
      expect(await forged.text()).toContain("SignatureDoesNotMatch");

      await client
        .startUserImportJob({ UserPoolId, JobId: job.JobId! })
        .promise();
      const late = await upload(job.PreSignedUrl!, `${HEADER}\n`);
      expect(late.status).toBe(403);
    });
  }),
);
