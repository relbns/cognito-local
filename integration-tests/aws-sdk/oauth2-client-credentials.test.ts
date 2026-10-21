import jwt from "jsonwebtoken";
import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "./setup";

const token = (url: string, body: Record<string, string>, auth?: string) =>
  fetch(`${url}/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...(auth ? { Authorization: auth } : {}),
    },
    body: new URLSearchParams(body).toString(),
  });

const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;

describe(
  "OAuth2 client_credentials grant",
  withCognitoSdk((Cognito, { serverUrl }) => {
    const setup = async (clientOverrides: Record<string, unknown> = {}) => {
      const client = Cognito();
      const pool = await client.createUserPool({ PoolName: "m2m" }).promise();
      const UserPoolId = pool.UserPool!.Id!;
      await client
        .createResourceServer({
          UserPoolId,
          Identifier: "orders.example.test",
          Name: "orders",
          Scopes: [
            { ScopeName: "read", ScopeDescription: "read" },
            { ScopeName: "write", ScopeDescription: "write" },
          ],
        })
        .promise();
      const created = await client
        .createUserPoolClient({
          UserPoolId,
          ClientName: "service",
          GenerateSecret: true,
          AllowedOAuthFlows: ["client_credentials"],
          AllowedOAuthFlowsUserPoolClient: true,
          AllowedOAuthScopes: ["orders.example.test/read"],
          ...clientOverrides,
        })
        .promise();
      return {
        UserPoolId,
        clientId: created.UserPoolClient!.ClientId!,
        secret: created.UserPoolClient!.ClientSecret!,
      };
    };

    it("issues an M2M access token with Basic authentication", async () => {
      const { UserPoolId, clientId, secret } = await setup();

      const res = await token(
        serverUrl(),
        { grant_type: "client_credentials", scope: "orders.example.test/read" },
        basic(clientId, secret),
      );

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(Object.keys(body).sort()).toEqual([
        "access_token",
        "expires_in",
        "token_type",
      ]);
      expect(body).toMatchObject({ expires_in: 3600, token_type: "Bearer" });
      const claims = jwt.decode(body.access_token) as Record<string, unknown>;
      expect(claims).toMatchObject({
        sub: clientId,
        client_id: clientId,
        token_use: "access",
        scope: "orders.example.test/read",
        version: 2,
      });
      expect(String(claims.iss)).toMatch(new RegExp(`/${UserPoolId}$`));
      expect(claims).not.toHaveProperty("username");
      expect(claims).not.toHaveProperty("origin_jti");
    });

    it("grants every allowed custom scope when scope is omitted, with the secret in the body", async () => {
      const { clientId, secret } = await setup();

      const res = await token(serverUrl(), {
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: secret,
      });

      const claims = jwt.decode((await res.json()).access_token) as {
        scope: string;
      };
      expect(claims.scope).toBe("orders.example.test/read");
    });

    it("answers Cognito's errors", async () => {
      const { clientId, secret } = await setup();
      const errorOf = async (body: Record<string, string>, auth?: string) => {
        const res = await token(
          serverUrl(),
          { grant_type: "client_credentials", ...body },
          auth,
        );
        return [res.status, await res.json()];
      };

      expect(await errorOf({}, basic(clientId, "wrong"))).toEqual([
        400,
        {
          error: "invalid_client",
          error_description: "Client authentication failed",
        },
      ]);
      expect(
        await errorOf(
          { scope: "orders.example.test/delete" },
          basic(clientId, secret),
        ),
      ).toEqual([400, { error: "invalid_scope" }]);
      expect(
        await errorOf(
          { scope: "orders.example.test/write" },
          basic(clientId, secret),
        ),
      ).toEqual([400, { error: "invalid_grant" }]);
    });

    it("refuses unauthorized_client when the client lacks the flow", async () => {
      const { clientId, secret } = await setup({
        AllowedOAuthFlows: ["code"],
        CallbackURLs: ["http://localhost:9876"],
      });

      const res = await token(
        serverUrl(),
        { grant_type: "client_credentials" },
        basic(clientId, secret),
      );

      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "unauthorized_client" });
    });

    it("refuses the M2M token on GetUser", async () => {
      const { clientId, secret } = await setup();
      const res = await token(
        serverUrl(),
        { grant_type: "client_credentials" },
        basic(clientId, secret),
      );
      const { access_token } = await res.json();

      await expect(
        Cognito().getUser({ AccessToken: access_token }).promise(),
      ).rejects.toMatchObject({ code: "NotAuthorizedException" });
    });
  }),
);
