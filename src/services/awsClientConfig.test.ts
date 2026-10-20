import { describe, expect, it } from "vitest";
import { toSdkV3ClientConfig } from "./awsClientConfig";

describe("toSdkV3ClientConfig", () => {
  it("passes SDK v3 options through without warnings", () => {
    const options = {
      region: "eu-west-1",
      endpoint: "http://localhost:3002",
      credentials: { accessKeyId: "a", secretAccessKey: "b" },
      maxAttempts: 2,
      retryMode: "standard",
      tls: false,
      requestHandler: {
        requestTimeout: 1000,
        connectionTimeout: 200,
        throwOnRequestTimeout: false,
      },
      customUserAgent: "agent",
      systemClockOffset: 5,
      useFipsEndpoint: false,
      useDualstackEndpoint: false,
    };

    expect(toSdkV3ClientConfig("LambdaClient", options)).toEqual({
      config: options,
      warnings: [],
    });
  });

  it("handles a missing section", () => {
    expect(toSdkV3ClientConfig("KMSConfig", undefined)).toEqual({
      config: {},
      warnings: [],
    });
  });

  it("keeps only the credential fields", () => {
    expect(
      toSdkV3ClientConfig("LambdaClient", {
        credentials: {
          accessKeyId: "a",
          secretAccessKey: "b",
          sessionToken: "c",
          expired: false,
        },
      }).config.credentials,
    ).toEqual({ accessKeyId: "a", secretAccessKey: "b", sessionToken: "c" });
  });

  it("maps the v2 options that have a v3 equivalent and says so", () => {
    expect(
      toSdkV3ClientConfig("LambdaClient", {
        accessKeyId: "a",
        secretAccessKey: "b",
        credentials: { accessKeyId: "local", secretAccessKey: "local" },
        maxRetries: 2,
        sslEnabled: false,
        httpOptions: { timeout: 1000, connectTimeout: 200 },
        endpoint: "localhost:3002",
      }),
    ).toEqual({
      config: {
        credentials: { accessKeyId: "a", secretAccessKey: "b" },
        maxAttempts: 3,
        tls: false,
        requestHandler: {
          requestTimeout: 1000,
          connectionTimeout: 200,
          throwOnRequestTimeout: true,
        },
        endpoint: "http://localhost:3002",
      },
      warnings: [
        "LambdaClient.accessKeyId/secretAccessKey is an AWS SDK v2 option; it is read as credentials. Use the SDK v3 name in config.json.",
        "LambdaClient.maxRetries is an AWS SDK v2 option; it is read as maxAttempts: 3. Use the SDK v3 name in config.json.",
        "LambdaClient.sslEnabled is an AWS SDK v2 option; it is read as tls: false. Use the SDK v3 name in config.json.",
        "LambdaClient.httpOptions.timeout is an AWS SDK v2 option; it is read as requestHandler.requestTimeout. Use the SDK v3 name in config.json.",
        "LambdaClient.httpOptions.connectTimeout is an AWS SDK v2 option; it is read as requestHandler.connectionTimeout. Use the SDK v3 name in config.json.",
        "LambdaClient.endpoint has no scheme; it is read as http://localhost:3002. Write the full URL in config.json.",
      ],
    });
  });

  it("reads a v2 endpoint object by its href", () => {
    expect(
      toSdkV3ClientConfig("KMSConfig", {
        endpoint: { href: "https://kms.example.test/" },
      }),
    ).toEqual({
      config: { endpoint: "https://kms.example.test/" },
      warnings: [],
    });
  });

  it("prefers the v3 option when both names are given", () => {
    const { config, warnings } = toSdkV3ClientConfig("LambdaClient", {
      maxAttempts: 5,
      maxRetries: 1,
      tls: true,
      sslEnabled: false,
    });

    expect(config).toEqual({ maxAttempts: 5, tls: true });
    expect(warnings).toEqual([
      "LambdaClient.maxRetries is ignored because maxAttempts is set.",
      "LambdaClient.sslEnabled is ignored because tls is set.",
    ]);
  });

  it("warns about every option it drops instead of dropping it silently", () => {
    const { config, warnings } = toSdkV3ClientConfig("KMSConfig", {
      region: "local",
      apiVersion: "2014-11-01",
      signatureVersion: "v4",
      logger: {},
      httpOptions: { agent: {}, timeout: "slow" },
      requestHandler: { httpAgent: {} },
      credentials: "profile",
      endpoint: 42,
    });

    expect(config).toEqual({ region: "local" });
    expect(warnings.sort()).toEqual(
      [
        "KMSConfig.apiVersion has no AWS SDK v3 equivalent and is ignored.",
        "KMSConfig.signatureVersion has no AWS SDK v3 equivalent and is ignored.",
        "KMSConfig.logger has no AWS SDK v3 equivalent and is ignored.",
        "KMSConfig.httpOptions.agent has no AWS SDK v3 equivalent and is ignored.",
        "KMSConfig.httpOptions.timeout has an invalid value and is ignored.",
        "KMSConfig.credentials has an invalid value and is ignored.",
        "KMSConfig.endpoint has an invalid value and is ignored.",
        "KMSConfig.requestHandler.httpAgent is not supported here and is ignored.",
      ].sort(),
    );
  });
});
