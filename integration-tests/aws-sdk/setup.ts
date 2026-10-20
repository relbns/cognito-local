import fs from "node:fs";
import type http from "node:http";
import { promisify } from "node:util";
import * as AWS from "aws-sdk";
import type { Logger } from "pino";
import { afterEach, beforeEach, vi } from "vitest";
import { createServer } from "../../src";
import { FakeMessageDeliveryService } from "../../src/__tests__/FakeMessageDeliveryService";
import { MockLogger } from "../../src/__tests__/mockLogger";
import { type Config, DefaultConfig } from "../../src/server/config";
import { Router } from "../../src/server/Router";
import {
  type Clock,
  DateClock,
  InMemoryAuthSessions,
  InMemoryCodeLog,
  type Lambda,
  MessagesService,
  TriggersService,
} from "../../src/services";
import {
  RecordingAuthSessions,
  RecordingMessages,
} from "../../src/services/codeLog";
import { CognitoServiceFactoryImpl } from "../../src/services/cognitoService";
import { CryptoService } from "../../src/services/crypto";
import type { DataStoreFactory } from "../../src/services/dataStore/factory";
import { StormDBDataStoreFactory } from "../../src/services/dataStore/stormDb";
import { otp } from "../../src/services/otp";
import { JwtTokenGenerator } from "../../src/services/tokenGenerator";
import { UserPoolServiceFactoryImpl } from "../../src/services/userPoolService";

const mkdtemp = promisify(fs.mkdtemp);
const rm = promisify(fs.rm);

export const withCognitoSdk =
  (
    fn: (
      cognito: () => AWS.CognitoIdentityServiceProvider,
      services: {
        readonly dataStoreFactory: () => DataStoreFactory;
        readonly messageDelivery: () => FakeMessageDeliveryService;
        readonly serverUrl: () => string;
      },
    ) => void,
    {
      logger = MockLogger as any,
      clock = new DateClock(),
      lambda,
      config = DefaultConfig,
    }: {
      logger?: Logger;
      clock?: Clock;
      lambda?: () => Lambda;
      config?: Config;
    } = {},
  ) =>
  () => {
    let dataDirectory: string;
    let httpServer: http.Server;
    let cognitoSdk: AWS.CognitoIdentityServiceProvider;
    let dataStoreFactory: DataStoreFactory;
    let fakeMessageDeliveryService: FakeMessageDeliveryService;
    let baseUrl: string;

    beforeEach(async () => {
      dataDirectory = await mkdtemp("/tmp/cognito-local:");
      const ctx = { logger };

      dataStoreFactory = new StormDBDataStoreFactory(dataDirectory);
      const cognitoServiceFactory = new CognitoServiceFactoryImpl(
        dataDirectory,
        dataStoreFactory,
        new UserPoolServiceFactoryImpl(clock, dataStoreFactory),
      );
      const cognitoClient = await cognitoServiceFactory.create(ctx, {});
      const triggers = new TriggersService(
        clock,
        cognitoClient,
        lambda?.() ?? {
          enabled: vi.fn().mockReturnValue(false),
          invoke: vi.fn(),
        },
        new CryptoService({ KMSKeyId: "", KMSKeyAlias: "" }),
      );

      fakeMessageDeliveryService = new FakeMessageDeliveryService();
      const codeLog = new InMemoryCodeLog(clock);
      const services = {
        authSessions: new RecordingAuthSessions(
          new InMemoryAuthSessions(clock),
          codeLog,
        ),
        clock,
        codeLog,
        cognito: cognitoClient,
        config,
        messages: new RecordingMessages(
          new MessagesService(triggers, fakeMessageDeliveryService),
          codeLog,
        ),
        otp,
        triggers,
        tokenGenerator: new JwtTokenGenerator(
          clock,
          triggers,
          DefaultConfig.TokenConfig,
        ),
      };
      const router = Router(services);
      const server = createServer(
        router,
        ctx.logger,
        {
          development: false,
          hostname: "127.0.0.1",
          https: false,
          port: 0,
        },
        services,
      );
      httpServer = await server.start();

      const address = httpServer.address();
      if (!address) {
        throw new Error("HttpServer has no address");
      }
      const url =
        typeof address === "string"
          ? address
          : `${address.address}:${address.port}`;

      baseUrl = `http://${url}`;

      cognitoSdk = new AWS.CognitoIdentityServiceProvider({
        credentials: {
          accessKeyId: "local",
          secretAccessKey: "local",
        },
        region: "local",
        endpoint: `http://${url}`,
      });
    });

    fn(() => cognitoSdk, {
      dataStoreFactory: () => dataStoreFactory,
      messageDelivery: () => fakeMessageDeliveryService,
      serverUrl: () => baseUrl,
    });

    afterEach(() => {
      return new Promise<void>((resolve, reject) => {
        httpServer.close(() => {
          rm(dataDirectory, {
            recursive: true,
          }).then(resolve, reject);
        });
      });
    });
  };
