export type AwsClientOptions = Record<string, unknown>;

export interface SdkV3Credentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export interface SdkV3ClientConfig {
  region?: string;
  endpoint?: string;
  credentials?: SdkV3Credentials;
  maxAttempts?: number;
  retryMode?: string;
  tls?: boolean;
  requestHandler?: {
    requestTimeout?: number;
    connectionTimeout?: number;
    throwOnRequestTimeout?: boolean;
  };
  customUserAgent?: string;
  systemClockOffset?: number;
  useFipsEndpoint?: boolean;
  useDualstackEndpoint?: boolean;
}

export interface MappedClientConfig {
  config: SdkV3ClientConfig;
  warnings: string[];
}

const PASSED_THROUGH = [
  "region",
  "maxAttempts",
  "retryMode",
  "tls",
  "customUserAgent",
  "systemClockOffset",
  "useFipsEndpoint",
  "useDualstackEndpoint",
] as const;

const HANDLED = new Set<string>([
  ...PASSED_THROUGH,
  "endpoint",
  "credentials",
  "requestHandler",
  "accessKeyId",
  "secretAccessKey",
  "sessionToken",
  "maxRetries",
  "sslEnabled",
  "httpOptions",
]);

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const pickCredentials = (
  source: Record<string, unknown>,
): SdkV3Credentials | undefined => {
  const { accessKeyId, secretAccessKey, sessionToken } = source;
  if (typeof accessKeyId !== "string" || typeof secretAccessKey !== "string") {
    return undefined;
  }
  return typeof sessionToken === "string"
    ? { accessKeyId, secretAccessKey, sessionToken }
    : { accessKeyId, secretAccessKey };
};

/** Maps a LambdaClient / KMSConfig section written for AWS SDK v2 onto the SDK v3 client options. */
export const toSdkV3ClientConfig = (
  section: string,
  options: AwsClientOptions | undefined,
): MappedClientConfig => {
  const config: SdkV3ClientConfig = {};
  const warnings: string[] = [];
  const source = options ?? {};
  const renamed = (key: string, replacement: string) =>
    warnings.push(
      `${section}.${key} is an AWS SDK v2 option; it is read as ${replacement}. Use the SDK v3 name in config.json.`,
    );
  const ignored = (key: string) =>
    warnings.push(
      `${section}.${key} has no AWS SDK v3 equivalent and is ignored.`,
    );
  const invalid = (key: string) =>
    warnings.push(`${section}.${key} has an invalid value and is ignored.`);
  const unsupported = (key: string) =>
    warnings.push(`${section}.${key} is not supported here and is ignored.`);
  const superseded = (key: string, by: string) =>
    warnings.push(`${section}.${key} is ignored because ${by} is set.`);

  for (const key of PASSED_THROUGH) {
    if (source[key] !== undefined) {
      (config as Record<string, unknown>)[key] = source[key];
    }
  }

  if (source.credentials !== undefined) {
    const credentials = isObject(source.credentials)
      ? pickCredentials(source.credentials)
      : undefined;
    if (credentials) config.credentials = credentials;
    else invalid("credentials");
  }
  if (
    source.accessKeyId !== undefined ||
    source.secretAccessKey !== undefined
  ) {
    const credentials = pickCredentials(source);
    if (credentials) {
      config.credentials = credentials;
      renamed("accessKeyId/secretAccessKey", "credentials");
    } else {
      invalid("accessKeyId/secretAccessKey");
    }
  }

  if (source.maxRetries !== undefined) {
    if (source.maxAttempts !== undefined) {
      superseded("maxRetries", "maxAttempts");
    } else if (typeof source.maxRetries === "number") {
      config.maxAttempts = source.maxRetries + 1;
      renamed("maxRetries", `maxAttempts: ${config.maxAttempts}`);
    } else {
      invalid("maxRetries");
    }
  }

  if (source.sslEnabled !== undefined) {
    if (source.tls !== undefined) {
      superseded("sslEnabled", "tls");
    } else if (typeof source.sslEnabled === "boolean") {
      config.tls = source.sslEnabled;
      renamed("sslEnabled", `tls: ${config.tls}`);
    } else {
      invalid("sslEnabled");
    }
  }

  const requestHandler: NonNullable<SdkV3ClientConfig["requestHandler"]> = {};
  if (isObject(source.requestHandler)) {
    for (const [key, value] of Object.entries(source.requestHandler)) {
      if (
        (key === "requestTimeout" || key === "connectionTimeout") &&
        typeof value === "number"
      ) {
        requestHandler[key] = value;
      } else if (
        key === "throwOnRequestTimeout" &&
        typeof value === "boolean"
      ) {
        requestHandler.throwOnRequestTimeout = value;
      } else {
        unsupported(`requestHandler.${key}`);
      }
    }
  } else if (source.requestHandler !== undefined) {
    invalid("requestHandler");
  }
  if (isObject(source.httpOptions)) {
    const timeouts = {
      timeout: "requestTimeout",
      connectTimeout: "connectionTimeout",
    } as const;
    for (const [key, value] of Object.entries(source.httpOptions)) {
      const v3Key = timeouts[key as keyof typeof timeouts];
      if (!v3Key) {
        ignored(`httpOptions.${key}`);
      } else if (typeof value !== "number") {
        invalid(`httpOptions.${key}`);
      } else if (requestHandler[v3Key] !== undefined) {
        superseded(`httpOptions.${key}`, `requestHandler.${v3Key}`);
      } else {
        requestHandler[v3Key] = value;
        if (key === "timeout") requestHandler.throwOnRequestTimeout ??= true;
        renamed(`httpOptions.${key}`, `requestHandler.${v3Key}`);
      }
    }
  } else if (source.httpOptions !== undefined) {
    invalid("httpOptions");
  }
  if (Object.keys(requestHandler).length)
    config.requestHandler = requestHandler;

  if (source.endpoint !== undefined) {
    const raw = isObject(source.endpoint)
      ? source.endpoint.href
      : source.endpoint;
    if (typeof raw === "string" && raw) {
      if (raw.includes("://")) {
        config.endpoint = raw;
      } else {
        config.endpoint = `${config.tls === false ? "http" : "https"}://${raw}`;
        warnings.push(
          `${section}.endpoint has no scheme; it is read as ${config.endpoint}. Write the full URL in config.json.`,
        );
      }
    } else {
      invalid("endpoint");
    }
  }

  for (const key of Object.keys(source)) {
    if (!HANDLED.has(key)) ignored(key);
  }

  return { config, warnings };
};
