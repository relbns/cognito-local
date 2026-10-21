import http from "node:http";
import type { AddressInfo } from "node:net";
import supertest from "supertest";
import { afterAll, beforeAll } from "vitest";

/**
 * supertest(app) listens on the wildcard address but connects to 127.0.0.1, so on macOS a server another
 * test file bound to 127.0.0.1 on the same port receives the request. This serves on 127.0.0.1 itself.
 */
export const localRequest = (): ((
  app: http.RequestListener,
) => ReturnType<typeof supertest>) => {
  let server: http.Server;
  let baseUrl = "";
  let current: http.RequestListener | undefined;

  beforeAll(async () => {
    server = http.createServer((req, res) => current?.(req, res));
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  return (app) => {
    current = app;
    return supertest(baseUrl);
  };
};
