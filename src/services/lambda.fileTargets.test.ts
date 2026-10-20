import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { TestContext } from "../__tests__/testContext";
import {
  InvalidLambdaResponseError,
  UnexpectedLambdaExceptionError,
  UserLambdaValidationError,
} from "../errors";
import { FileTriggerInvoker } from "./fileTrigger";
import { type LambdaClient, LambdaService } from "./lambda";

describe("LambdaService with file: targets", () => {
  let dir: string;
  const lambdaClient = { invoke: vi.fn() } as unknown as LambdaClient;

  const write = (name: string, body: string) => {
    const file = path.join(dir, name);
    fs.writeFileSync(file, body);
    return file;
  };

  const preSignUpEvent = (userPoolId = "local_pool") =>
    ({
      clientId: "client",
      clientMetadata: { a: "b" },
      triggerSource: "PreSignUp_SignUp",
      userAttributes: { email: "user@example.test" },
      username: "user",
      userPoolId,
      validationData: undefined,
    }) as const;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "cognito-local-lambda-"));
    write(
      "presignup.js",
      "exports.handler = async (event) => { const seen = JSON.parse(JSON.stringify(event)); event.response.autoConfirmUser = true; event.response.seen = seen; return event; };",
    );
    write(
      "presignup-other.js",
      "exports.confirm = async (event) => ({ ...event, response: { autoConfirmUser: false, autoVerifyEmail: true } });",
    );
    write(
      "throws.js",
      "exports.handler = async () => { throw new Error('No sign-ups today'); };",
    );
    write("hangs.js", "exports.handler = () => new Promise(() => {});");
    write("no-response.js", "exports.handler = async () => undefined;");
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("invokes a file from the global config with the AWS event shape, relative to baseDir", async () => {
    const lambda = new LambdaService(
      { PreSignUp: "file:./presignup.js" },
      lambdaClient,
      { baseDir: dir },
    );

    expect(lambda.enabled("PreSignUp")).toBe(true);
    const response = (await lambda.invoke(
      TestContext,
      "PreSignUp",
      preSignUpEvent(),
    )) as Record<string, unknown>;

    expect(lambdaClient.invoke).not.toHaveBeenCalled();
    expect(response.autoConfirmUser).toBe(true);
    expect(response.seen).toMatchObject({
      version: "0",
      region: "local",
      userPoolId: "local_pool",
      triggerSource: "PreSignUp_SignUp",
      userName: "user",
      callerContext: { clientId: "client" },
      request: {
        userAttributes: { email: "user@example.test" },
        clientMetadata: { a: "b" },
      },
    });
  });

  it("prefers a pool's file: LambdaConfig entry, and ignores its non-file entries", async () => {
    const pools: Record<string, Record<string, unknown>> = {
      local_pool: {
        PreSignUp: `file:${path.join(dir, "presignup-other.js")}#confirm`,
        PostConfirmation: "arn:aws:lambda:us-east-1:123:function:real",
        CustomEmailSender: {
          LambdaArn: `file:${path.join(dir, "presignup.js")}`,
          LambdaVersion: "V1_0",
        },
      },
    };
    const lambda = new LambdaService(
      { PreSignUp: "GlobalPreSignUp" },
      lambdaClient,
      { poolLambdaConfig: (id) => pools[id] },
    );

    expect(lambda.enabled("PreSignUp", "local_pool")).toBe(true);
    expect(lambda.enabled("PostConfirmation", "local_pool")).toBe(false);
    expect(lambda.enabled("CustomEmailSender", "local_pool")).toBe(true);
    expect(lambda.enabled("CustomEmailSender", "local_other")).toBe(false);

    await expect(
      lambda.invoke(TestContext, "PreSignUp", preSignUpEvent()),
    ).resolves.toEqual({ autoConfirmUser: false, autoVerifyEmail: true });
  });

  it("surfaces a thrown error the way Cognito does", async () => {
    const lambda = new LambdaService(
      { PreSignUp: `file:${path.join(dir, "throws.js")}` },
      lambdaClient,
    );
    await expect(
      lambda.invoke(TestContext, "PreSignUp", preSignUpEvent()),
    ).rejects.toEqual(
      new UserLambdaValidationError(
        "PreSignUp failed with error No sign-ups today.",
      ),
    );
  });

  it("fails a trigger that runs past the timeout", async () => {
    const lambda = new LambdaService(
      { PreSignUp: `file:${path.join(dir, "hangs.js")}` },
      lambdaClient,
      { files: new FileTriggerInvoker({ timeoutMs: 30 }) },
    );
    await expect(
      lambda.invoke(TestContext, "PreSignUp", preSignUpEvent()),
    ).rejects.toEqual(
      new UnexpectedLambdaExceptionError(
        "PreSignUp invocation failed due to error Task timed out after 0.03 seconds.",
      ),
    );
  });

  it("rejects a handler that does not return the event", async () => {
    const lambda = new LambdaService(
      { PreSignUp: `file:${path.join(dir, "no-response.js")}` },
      lambdaClient,
    );
    await expect(
      lambda.invoke(TestContext, "PreSignUp", preSignUpEvent()),
    ).rejects.toEqual(new InvalidLambdaResponseError());
  });

  it("reports a missing file as an unexpected Lambda exception", async () => {
    const lambda = new LambdaService(
      { PreSignUp: `file:${path.join(dir, "missing.js")}` },
      lambdaClient,
    );
    await expect(
      lambda.invoke(TestContext, "PreSignUp", preSignUpEvent()),
    ).rejects.toBeInstanceOf(UnexpectedLambdaExceptionError);
  });
});
