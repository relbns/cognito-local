#!/usr/bin/env node

import * as https from "node:https";
import Pino from "pino";
import PinoPretty from "pino-pretty";
import { createDefaultServer } from "../server";

const logger = Pino(
  {
    level: process.env.DEBUG ? "debug" : "info",
  },
  PinoPretty({
    colorize: true,
    ignore: "pid,name,hostname",
    singleLine: true,
    messageFormat: (log, messageKey) =>
      `${log.reqId ?? "NONE"} ${log.target ?? "NONE"} ${log[messageKey]}`,
  }),
);

let adminUiPath: string | undefined;

createDefaultServer(logger)
  .then((server) => {
    adminUiPath = server.adminUiPath;
    return server.start();
  })
  .then((server) => {
    const address = server.address();
    if (!address) {
      throw new Error("Server started without address");
    }
    const url =
      typeof address === "string"
        ? address
        : `${address.address}:${address.port}`;

    const proto = server instanceof https.Server ? "https" : "http";

    logger.info(`Cognito Local running on ${proto}://${url}`);
    if (adminUiPath) {
      logger.info(
        `Admin UI on ${proto}://${url}${adminUiPath} (no authentication, local development only)`,
      );
    }
  })
  .catch((err) => {
    logger.error(err);
    process.exit(1);
  });
