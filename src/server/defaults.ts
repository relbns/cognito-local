import path from "node:path";
import { Lambda } from "@aws-sdk/client-lambda";
import type pino from "pino";
import { applySeed, formatSeedResult, loadSeedFile } from "../seed";
import type { SeedResult } from "../seed/types";
import {
  DateClock,
  InMemoryAuthSessions,
  InMemoryCodeLog,
  LambdaService,
  MessagesService,
  type Services,
  TriggersService,
} from "../services";
import { toSdkV3ClientConfig } from "../services/awsClientConfig";
import { RecordingAuthSessions, RecordingMessages } from "../services/codeLog";
import { CognitoServiceFactoryImpl } from "../services/cognitoService";
import { CryptoService } from "../services/crypto";
import { StormDBDataStoreFactory } from "../services/dataStore/stormDb";
import { FileTriggerInvoker } from "../services/fileTrigger";
import { ConsoleMessageSender } from "../services/messageDelivery/consoleMessageSender";
import { MessageDeliveryService } from "../services/messageDelivery/messageDelivery";
import type { MessageSender } from "../services/messageDelivery/messageSender";
import { SmtpMessageSender } from "../services/messageDelivery/smtpMessageSender";
import { otp } from "../services/otp";
import { JwtTokenGenerator } from "../services/tokenGenerator";
import { UserPoolServiceFactoryImpl } from "../services/userPoolService";
import { type ConfigOverrides, loadConfig } from "./config";
import { Router } from "./Router";
import { createServer, type Server } from "./server";

export const DEFAULT_DATA_DIRECTORY = ".cognito";

export interface DefaultServerOptions extends ConfigOverrides {
  /** Holds config.json and db/; defaults to COGNITO_LOCAL_DATA_DIR or .cognito. */
  dataDirectory?: string;
  /** Seed file applied before the server starts; defaults to COGNITO_LOCAL_SEED. */
  seedFile?: string;
}

export const resolveDataDirectory = (dataDirectory?: string): string =>
  dataDirectory || process.env.COGNITO_LOCAL_DATA_DIR || DEFAULT_DATA_DIRECTORY;

export interface DefaultServices {
  services: Services;
  router: Router;
  dataDirectory: string;
}

export const createDefaultServices = async (
  logger: pino.Logger,
  options: DefaultServerOptions = {},
): Promise<DefaultServices> => {
  const configDirectory = resolveDataDirectory(options.dataDirectory);
  const dataDirectory = `${configDirectory}/db`;
  const ctx = {
    logger,
  };

  const config = await loadConfig(
    ctx,
    // the config gets a separate factory because it's stored in a different directory
    new StormDBDataStoreFactory(configDirectory),
    options,
  );

  logger.debug({ config }, "Loaded config");

  const clock = new DateClock();

  const dataStoreFactory = new StormDBDataStoreFactory(dataDirectory);

  const cognitoServiceFactory = new CognitoServiceFactoryImpl(
    dataDirectory,
    dataStoreFactory,
    new UserPoolServiceFactoryImpl(clock, dataStoreFactory),
  );
  const cognitoClient = await cognitoServiceFactory.create(
    ctx,
    config.UserPoolDefaults,
  );
  const lambdaClient = toSdkV3ClientConfig("LambdaClient", config.LambdaClient);
  const { KMSKeyId, KMSKeyAlias, ...kmsOptions } = config.KMSConfig ?? {};
  const kmsClient = toSdkV3ClientConfig("KMSConfig", kmsOptions);
  for (const warning of [...lambdaClient.warnings, ...kmsClient.warnings]) {
    logger.warn(warning);
  }

  const triggers = new TriggersService(
    clock,
    cognitoClient,
    new LambdaService(
      config.TriggerFunctions,
      new Lambda(lambdaClient.config),
      {
        baseDir: path.resolve(configDirectory),
        poolLambdaConfig: (userPoolId) =>
          cognitoClient.peekUserPool(userPoolId)?.LambdaConfig as
            | Record<string, unknown>
            | undefined,
        files: new FileTriggerInvoker({
          timeoutMs: config.FileTriggerConfig.TimeoutMs,
          hotReload: config.FileTriggerConfig.HotReload,
        }),
      },
    ),
    new CryptoService({ KMSKeyId, KMSKeyAlias }, kmsClient.config),
  );

  // Use SMTP sender (e.g. MailHog) when SMTP_HOST is set, otherwise log to console
  const smtpHost = process.env.SMTP_HOST;
  const smtpPort = Number(process.env.SMTP_PORT ?? "1025");
  const messageSender: MessageSender = smtpHost
    ? new SmtpMessageSender(smtpHost, smtpPort)
    : new ConsoleMessageSender();

  if (smtpHost) {
    logger.info(`Email delivery via SMTP: ${smtpHost}:${smtpPort}`);
  }

  const authSessions = new InMemoryAuthSessions(
    clock,
    config.AuthSessionConfig.AuthSessionValidity,
  );
  const messages = new MessagesService(
    triggers,
    new MessageDeliveryService(messageSender),
  );
  const codeLog = config.AdminUIConfig.Enabled
    ? new InMemoryCodeLog(clock, config.AdminUIConfig.CodeLogSize)
    : undefined;

  const services: Services = {
    authSessions: codeLog
      ? new RecordingAuthSessions(authSessions, codeLog)
      : authSessions,
    clock,
    codeLog,
    cognito: cognitoClient,
    config,
    messages: codeLog ? new RecordingMessages(messages, codeLog) : messages,
    otp,
    tokenGenerator: new JwtTokenGenerator(clock, triggers, config.TokenConfig),
    triggers,
  };

  return { services, router: Router(services), dataDirectory: configDirectory };
};

export type DefaultServer = Server & {
  services: Services;
  dataDirectory: string;
  seedResult?: SeedResult;
};

export const createDefaultServer = async (
  logger: pino.Logger,
  options: DefaultServerOptions = {},
): Promise<DefaultServer> => {
  const { services, router, dataDirectory } = await createDefaultServices(
    logger,
    options,
  );

  const seedFile = options.seedFile || process.env.COGNITO_LOCAL_SEED;
  let seedResult: SeedResult | undefined;
  if (seedFile) {
    const source = path.resolve(seedFile);
    seedResult = await applySeed(
      { logger },
      services,
      loadSeedFile(source),
      source,
    );
    const lines = formatSeedResult(seedResult);
    logger.info(
      `Applied seed ${source}: ${lines.length ? `${lines.length} change(s)` : "no changes"}`,
    );
    for (const line of lines) logger.info(`  ${line}`);
  }

  return {
    ...createServer(router, logger, services.config.ServerConfig, services),
    services,
    dataDirectory,
    seedResult,
  };
};
