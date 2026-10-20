import mergeWith from "lodash.mergewith";
import { DEFAULT_AUTH_SESSION_VALIDITY_MINUTES } from "../services/authSessions";
import type { Context } from "../services/context";
import type { KMSConfig } from "../services/crypto";
import type { DataStoreFactory } from "../services/dataStore/factory";
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

export interface PasswordPolicyConfig {
  Enforce: boolean;
}

export interface Config {
  LambdaClient: AWS.Lambda.ClientConfiguration;
  TriggerFunctions: FunctionConfig;
  UserPoolDefaults: UserPoolDefaults;
  KMSConfig?: AWS.KMS.ClientConfiguration & KMSConfig;
  ServerConfig: ServerOptions;
  TokenConfig: TokenConfig;
  AuthSessionConfig: AuthSessionConfig;
  PasswordPolicyConfig: PasswordPolicyConfig;
}

const port = parseInt(process.env.PORT ?? "9229", 10);
const hostname = process.env.HOST ?? "localhost";

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
  PasswordPolicyConfig: {
    Enforce: true,
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
