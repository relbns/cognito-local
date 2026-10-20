import mergeWith from "lodash.mergewith";
import { DEFAULT_AUTH_SESSION_VALIDITY_MINUTES } from "../services/authSessions";
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

export interface FileTriggerConfig {
  /** How long a file: trigger may run before it fails, like a Lambda timeout. */
  TimeoutMs: number;
  /** Reload a trigger module when its file changes. */
  HotReload: boolean;
}

export interface Config {
  LambdaClient: AWS.Lambda.ClientConfiguration;
  TriggerFunctions: FunctionConfig;
  UserPoolDefaults: UserPoolDefaults;
  KMSConfig?: AWS.KMS.ClientConfiguration & KMSConfig;
  ServerConfig: ServerOptions;
  TokenConfig: TokenConfig;
  AuthSessionConfig: AuthSessionConfig;
  AdminUIConfig: AdminUIConfig;
  PasswordPolicyConfig: PasswordPolicyConfig;
  FileTriggerConfig: FileTriggerConfig;
}

const port = parseInt(process.env.PORT ?? "9229", 10);
const hostname = process.env.HOST ?? "localhost";
const adminUIEnabled = !["0", "false", "off"].includes(
  (process.env.COGNITO_LOCAL_ADMIN_UI ?? "").toLowerCase(),
);

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
    IssuerDomain: `http://${hostname}:${port}`,
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
): Promise<Config> => {
  ctx.logger.debug("loadConfig");
  const dataStore = await dataStoreFactory.create(ctx, "config", {});

  const config = await dataStore.getRoot<Config>(ctx);

  return mergeWith(
    {},
    DefaultConfig,
    config ?? {},
    function customizer(_objValue, srcValue) {
      if (Array.isArray(srcValue)) {
        return srcValue;
      }
    },
  );
};
