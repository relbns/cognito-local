import { randomBytes } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { Lambda } from "@aws-sdk/client-lambda";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TestContext } from "../src/__tests__/testContext";
import { UserLambdaValidationError } from "../src/errors";
import { toSdkV3ClientConfig } from "../src/services/awsClientConfig";
import { CryptoService } from "../src/services/crypto";
import { LambdaService } from "../src/services/lambda";

const KEY_ARN =
  "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000";

interface Received {
  path: string;
  target?: string;
  authorization?: string;
  body: string;
}

describe("SDK v3 Lambda and KMS clients against a local endpoint", () => {
  const received: Received[] = [];
  let server: http.Server;
  let endpoint: string;

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", () => {
        const target = req.headers["x-amz-target"] as string | undefined;
        received.push({
          path: req.url ?? "",
          target,
          authorization: req.headers.authorization,
          body,
        });

        if (req.url?.startsWith("/2015-03-31/functions/")) {
          const event = JSON.parse(body);
          if (req.url.includes("/failing/")) {
            res.setHeader("X-Amz-Function-Error", "Unhandled");
            res.end(JSON.stringify({ errorMessage: "trigger blew up" }));
            return;
          }
          event.response.autoConfirmUser = true;
          res.end(JSON.stringify(event));
          return;
        }

        const request = JSON.parse(body);
        res.setHeader("Content-Type", "application/x-amz-json-1.1");
        if (target === "TrentService.GenerateDataKey") {
          res.end(
            JSON.stringify({
              KeyId: KEY_ARN,
              Plaintext: randomBytes(request.NumberOfBytes).toString("base64"),
              CiphertextBlob: randomBytes(64).toString("base64"),
            }),
          );
          return;
        }
        if (target === "TrentService.Encrypt") {
          res.end(
            JSON.stringify({
              KeyId: KEY_ARN,
              CiphertextBlob: randomBytes(64).toString("base64"),
            }),
          );
          return;
        }
        res.statusCode = 400;
        res.end(JSON.stringify({ __type: "UnknownOperationException" }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));
    endpoint = `http://localhost:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise((resolve) => server.close(resolve)));

  const clientConfig = (extra: Record<string, unknown> = {}) =>
    toSdkV3ClientConfig("Test", {
      region: "us-east-1",
      credentials: { accessKeyId: "local", secretAccessKey: "local" },
      endpoint,
      ...extra,
    }).config;

  const preSignUp = (lambda: LambdaService) =>
    lambda.invoke(TestContext, "PreSignUp", {
      clientId: "client",
      clientMetadata: undefined,
      triggerSource: "PreSignUp_SignUp",
      username: "user",
      userPoolId: "pool",
      userAttributes: { email: "user@example.test" },
      validationData: undefined,
    });

  it("invokes a trigger through the Lambda REST API and reads its response", async () => {
    const lambda = new LambdaService(
      { PreSignUp: "pre-sign-up" },
      new Lambda(clientConfig()),
    );

    const response = await preSignUp(lambda);

    expect(response).toEqual(
      expect.objectContaining({ autoConfirmUser: true }),
    );
    const call = received.find((r) => r.path.includes("/pre-sign-up/"));
    expect(call?.authorization).toContain("Credential=local/");
    expect(JSON.parse(call?.body ?? "{}")).toEqual(
      expect.objectContaining({
        triggerSource: "PreSignUp_SignUp",
        callerContext: {
          awsSdkVersion: "aws-sdk-unknown-unknown",
          clientId: "client",
        },
      }),
    );
  });

  it("turns an unhandled function error into UserLambdaValidationError", async () => {
    const lambda = new LambdaService(
      { PreSignUp: "failing" },
      new Lambda(clientConfig()),
    );

    await expect(preSignUp(lambda)).rejects.toEqual(
      new UserLambdaValidationError(
        "PreSignUp failed with error trigger blew up.",
      ),
    );
  });

  it("works with a v2-style config mapped onto the v3 client", async () => {
    const lambda = new LambdaService(
      { PreSignUp: "pre-sign-up" },
      new Lambda(
        toSdkV3ClientConfig("LambdaClient", {
          region: "us-east-1",
          accessKeyId: "v2key",
          secretAccessKey: "v2secret",
          sslEnabled: false,
          maxRetries: 0,
          endpoint: endpoint.replace("http://", ""),
        }).config,
      ),
    );

    await expect(preSignUp(lambda)).resolves.toEqual(
      expect.objectContaining({ autoConfirmUser: true }),
    );
    expect(received.at(-1)?.authorization).toContain("Credential=v2key/");
  });

  it("uses the default credential and region chains when credentials and region are null", async () => {
    const saved = {
      AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
      AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
      AWS_REGION: process.env.AWS_REGION,
    };
    process.env.AWS_ACCESS_KEY_ID = "envkey";
    process.env.AWS_SECRET_ACCESS_KEY = "envsecret";
    process.env.AWS_REGION = "eu-west-2";
    try {
      const mapped = toSdkV3ClientConfig("LambdaClient", {
        credentials: null,
        region: null,
        endpoint,
      });
      expect(mapped.warnings).toEqual([]);
      const lambda = new LambdaService(
        { PreSignUp: "pre-sign-up" },
        new Lambda(mapped.config),
      );

      await expect(preSignUp(lambda)).resolves.toEqual(
        expect.objectContaining({ autoConfirmUser: true }),
      );
      expect(received.at(-1)?.authorization).toContain("Credential=envkey/");
      expect(received.at(-1)?.authorization).toContain("/eu-west-2/lambda/");
    } finally {
      for (const [key, value] of Object.entries(saved)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
  });

  it("encrypts a code with the KMS keyring for custom sender triggers", async () => {
    const crypto = new CryptoService(
      { KMSKeyAlias: "alias/test", KMSKeyId: KEY_ARN },
      clientConfig(),
    );

    const encrypted = await crypto.encrypt(TestContext, "123456");

    expect(Buffer.from(encrypted, "base64").length).toBeGreaterThan(0);
    expect(
      received.filter((r) => r.target?.startsWith("TrentService.")),
    ).toEqual([
      expect.objectContaining({ target: "TrentService.GenerateDataKey" }),
      expect.objectContaining({ target: "TrentService.Encrypt" }),
    ]);
  });
});
