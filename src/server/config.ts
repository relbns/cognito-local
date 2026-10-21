import mergeWith from "lodash.mergewith";
import { DEFAULT_AUTH_SESSION_VALIDITY_MINUTES } from "../services/authSessions";
import type { AwsClientOptions } from "../services/awsClientConfig";
import { DEFAULT_CODE_LOG_SIZE } from "../services/codeLog";
import type { Context } from "../services/context";
import type { KMSConfig } from "../services/crypto";
import type { DataStoreFactory } from "../services/dataStore/factory";
import { DEFAULT_FILE_TRIGGER_TIMEOUT_MS } from "../services/fileTrigger";
import type { FunctionConfig } from "../services/lambda";
import { DEFAULT_PASSWORD_RESET_ATTEMPTS_PER_HOUR } from "../services/signInLockout";
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
  /** When set, /_admin and /_admin/api/* require this token. */
  Token?: string;
}

export interface PasswordPolicyConfig {
  Enforce: boolean;
}

export interface LockoutConfig {
  /** Lock a user out after five failed passwords, and limit password reset attempts. */
  Enabled: boolean;
  /** ForgotPassword requests and ConfirmForgotPassword attempts per user per hour; 0 for no limit. */
  PasswordResetAttemptsPerHour: number;
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

export type FederationMode = "mock" | "real";

export interface FederationProviderConfig {
  Mode?: FederationMode;
}

export interface FederationConfig {
  /** "real" sends OIDC and social sign-ins to the provider itself; "mock" shows the mock IdP page. */
  Mode: FederationMode;
  /** Per-provider override, keyed by ProviderName. */
  Providers: Record<string, FederationProviderConfig>;
}

export interface ConfigOverrides {
  port?: number;
  hostname?: string;
  adminUi?: boolean;
  adminToken?: string;
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
  LockoutConfig: LockoutConfig;
  ValidationConfig: ValidationConfig;
  FileTriggerConfig: FileTriggerConfig;
  FederationConfig: FederationConfig;
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
    Token: process.env.COGNITO_LOCAL_ADMIN_TOKEN || undefined,
  },
  PasswordPolicyConfig: {
    Enforce: true,
  },
  LockoutConfig: {
    Enabled: true,
    PasswordResetAttemptsPerHour: DEFAULT_PASSWORD_RESET_ATTEMPTS_PER_HOUR,
  },
  ValidationConfig: {
    Enabled: !isOff(process.env.COGNITO_LOCAL_VALIDATION),
  },
  FileTriggerConfig: {
    TimeoutMs: DEFAULT_FILE_TRIGGER_TIMEOUT_MS,
    HotReload: true,
  },
  FederationConfig: {
    Mode: "mock",
    Providers: {},
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

const FEDERATION_MODES: readonly unknown[] = ["mock", "real"];

function assertFederationConfig(federation: FederationConfig): void {
  if (!FEDERATION_MODES.includes(federation.Mode)) {
    throw new Error(
      `FederationConfig.Mode must be "mock" or "real", got ${JSON.stringify(federation.Mode)}`,
    );
  }
  for (const [name, provider] of Object.entries(federation.Providers ?? {})) {
    if (
      provider?.Mode !== undefined &&
      !FEDERATION_MODES.includes(provider.Mode)
    ) {
      throw new Error(
        `FederationConfig.Providers.${name}.Mode must be "mock" or "real", got ${JSON.stringify(provider.Mode)}`,
      );
    }
  }
}

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
  if (overrides.adminToken !== undefined) {
    merged.AdminUIConfig.Token = overrides.adminToken;
  }
  assertFederationConfig(merged.FederationConfig);
  if (!config?.TokenConfig?.IssuerDomain) {
    const proto = merged.ServerConfig.https ? "https" : "http";
    merged.TokenConfig.IssuerDomain = `${proto}://${issuerHostFor(merged.ServerConfig.hostname)}:${merged.ServerConfig.port}`;
  }

  return merged;
};
