import mergeWith from "lodash.mergewith";
import { DEFAULT_AUTH_SESSION_VALIDITY_MINUTES } from "../services/authSessions";
import type { AwsClientOptions } from "../services/awsClientConfig";
import { DEFAULT_CODE_LOG_SIZE } from "../services/codeLog";
import type { Context } from "../services/context";
import type { KMSConfig } from "../services/crypto";
import type { DataStoreFactory } from "../services/dataStore/factory";
import { DEFAULT_FILE_TRIGGER_TIMEOUT_MS } from "../services/fileTrigger";
import type { FunctionConfig } from "../services/lambda";
import type { TokenConfig } from "../services/tokenGenerator";
import type { UserPool } from "../services/userPoolService";
import type { ServerOptions } from "./server";

export type UserPoolDefaults = Omit<
  UserPool,
  "Id" | "CreationDate" | "LastModifiedDate"
>;

export interface AuthSessionConfig {
  AuthSessionValidity: number;
}

export interface AdminUIConfig {
  Enabled: boolean;
  CodeLogSize: number;
}

export interface PasswordPolicyConfig {
  Enforce: boolean;
}

export interface ValidationConfig {
  /** Check every request against the service's input model before the target runs. */
  Enabled: boolean;
}

export interface FileTriggerConfig {
  /** How long a file: trigger may run before it fails, like a Lambda timeout. */
  TimeoutMs: number;
  /** Reload a trigger module when its file changes. */
  HotReload: boolean;
}

export interface ConfigOverrides {
  port?: number;
  hostname?: string;
  adminUi?: boolean;
}

export interface Config {
  LambdaClient: AwsClientOptions;
  TriggerFunctions: FunctionConfig;
  UserPoolDefaults: UserPoolDefaults;
  KMSConfig?: AwsClientOptions & KMSConfig;
  ServerConfig: ServerOptions;
  TokenConfig: TokenConfig;
  AuthSessionConfig: AuthSessionConfig;
  AdminUIConfig: AdminUIConfig;
  PasswordPolicyConfig: PasswordPolicyConfig;
  ValidationConfig: ValidationConfig;
  FileTriggerConfig: FileTriggerConfig;
}

const port = parseInt(process.env.PORT ?? "9229", 10);
const hostname = process.env.HOST ?? "localhost";
const issuerHostFor = (host: string | undefined): string | undefined =>
  ["0.0.0.0", "::", "[::]"].includes(host ?? "") ? "localhost" : host;
const isOff = (value: string | undefined): boolean =>
  ["0", "false", "off"].includes((value ?? "").toLowerCase());
const adminUIEnabled = !isOff(process.env.COGNITO_LOCAL_ADMIN_UI);

export const DefaultConfig: Config = {
  LambdaClient: {
    credentials: {
      accessKeyId: "local",
      secretAccessKey: "local",
    },
    region: "local",
  },
  TriggerFunctions: {},
  UserPoolDefaults: {
    UsernameAttributes: ["email"],
  },
  TokenConfig: {
    IssuerDomain: `http://${issuerHostFor(hostname)}:${port}`,
    Verify: true,
    CheckSecretHash: true,
  },
  AuthSessionConfig: {
    AuthSessionValidity: DEFAULT_AUTH_SESSION_VALIDITY_MINUTES,
  },
  AdminUIConfig: {
    Enabled: adminUIEnabled,
    CodeLogSize: DEFAULT_CODE_LOG_SIZE,
  },
  PasswordPolicyConfig: {
    Enforce: true,
  },
  ValidationConfig: {
    Enabled: !isOff(process.env.COGNITO_LOCAL_VALIDATION),
  },
  FileTriggerConfig: {
    TimeoutMs: DEFAULT_FILE_TRIGGER_TIMEOUT_MS,
    HotReload: true,
  },
  KMSConfig: {
    credentials: {
      accessKeyId: "local",
      secretAccessKey: "local",
    },
    region: "local",
  },
  ServerConfig: {
    port,
    hostname,
    development: !!process.env.COGNITO_LOCAL_DEVMODE,
    https: false,
  },
};

export const loadConfig = async (
  ctx: Context,
  dataStoreFactory: DataStoreFactory,
  overrides: ConfigOverrides = {},
): Promise<Config> => {
  ctx.logger.debug("loadConfig");
  const dataStore = await dataStoreFactory.create(ctx, "config", {});

  const config = await dataStore.getRoot<Partial<Config>>(ctx);

  const merged: Config = mergeWith(
    {},
    DefaultConfig,
    config ?? {},
    function customizer(_objValue, srcValue) {
      if (Array.isArray(srcValue)) {
        return srcValue;
      }
    },
  );

  if (overrides.port !== undefined) merged.ServerConfig.port = overrides.port;
  if (overrides.hostname !== undefined) {
    merged.ServerConfig.hostname = overrides.hostname;
  }
  if (overrides.adminUi !== undefined) {
    merged.AdminUIConfig.Enabled = overrides.adminUi;
  }
  if (!config?.TokenConfig?.IssuerDomain) {
    const proto = merged.ServerConfig.https ? "https" : "http";
    merged.TokenConfig.IssuerDomain = `${proto}://${issuerHostFor(merged.ServerConfig.hostname)}:${merged.ServerConfig.port}`;
  }

  return merged;
};
