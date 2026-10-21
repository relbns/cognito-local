import http from "node:http";
import jwt from "jsonwebtoken";
import { describe, expect, it } from "vitest";
import { DefaultConfig } from "../../src/server/config";
import { withCognitoSdk } from "./setup";

const PASSWORD = "Passw0rd!";

const request = (
  url: string,
  path: string,
  host: string,
  options: { target?: string; body?: unknown } = {},
): Promise<{ status: number; body: Record<string, unknown> }> =>
  new Promise((resolve, reject) => {
    const target = new URL(path, url);
    const payload = options.body ? JSON.stringify(options.body) : undefined;
    const req = http.request(
      {
        hostname: target.hostname,
        port: target.port,
        path: target.pathname,
        method: payload ? "POST" : "GET",
        headers: {
          Host: host,
          ...(options.target
            ? {
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": `AWSCognitoIdentityProviderService.${options.target}`,
              }
            : {}),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => {
          data += chunk;
        });
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, body: JSON.parse(data) }),
        );
      },
    );
    req.on("error", reject);
    req.end(payload);
  });

const config = {
  ...DefaultConfig,
  TokenConfig: { ...DefaultConfig.TokenConfig, IssuerFromRequest: true },
};

describe(
  "TokenConfig.IssuerFromRequest",
  withCognitoSdk(
    (Cognito, { serverUrl }) => {
      const setup = async () => {
        const client = Cognito();
        const pool = await client
          .createUserPool({ PoolName: "issuer", UsernameAttributes: [] })
          .promise();
        const UserPoolId = pool.UserPool!.Id!;
        const app = await client
          .createUserPoolClient({ UserPoolId, ClientName: "web" })
          .promise();
        await client
          .adminCreateUser({
            UserPoolId,
            Username: "jane",
            MessageAction: "SUPPRESS",
          })
          .promise();
        await client
          .adminSetUserPassword({
            UserPoolId,
            Username: "jane",
            Password: PASSWORD,
            Permanent: true,
          })
          .promise();
        return { UserPoolId, ClientId: app.UserPoolClient!.ClientId! };
      };

      it("issues tokens for the Host header and accepts them under another host", async () => {
        const { UserPoolId, ClientId } = await setup();

        const auth = await request(serverUrl(), "/", "localhost:32768", {
          target: "InitiateAuth",
          body: {
            ClientId,
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: { USERNAME: "jane", PASSWORD },
          },
        });
        const result = auth.body.AuthenticationResult as Record<string, string>;
        expect(jwt.decode(result.AccessToken)).toMatchObject({
          iss: `http://localhost:32768/${UserPoolId}`,
        });
        expect(jwt.decode(result.IdToken)).toMatchObject({
          iss: `http://localhost:32768/${UserPoolId}`,
        });

        const user = await Cognito()
          .getUser({ AccessToken: result.AccessToken })
          .promise();
        expect(user.Username).toBe("jane");
        const refreshed = await Cognito()
          .initiateAuth({
            ClientId,
            AuthFlow: "REFRESH_TOKEN_AUTH",
            AuthParameters: { REFRESH_TOKEN: result.RefreshToken },
          })
          .promise();
        expect(
          jwt.decode(refreshed.AuthenticationResult!.AccessToken!),
        ).toMatchObject({
          iss: `${serverUrl()}/${UserPoolId}`,
        });
      });

      it("serves discovery for the Host header", async () => {
        const { UserPoolId } = await setup();

        const discovery = await request(
          serverUrl(),
          `/${UserPoolId}/.well-known/openid-configuration`,
          "cognito.example.test:4566",
        );

        expect(discovery.body).toMatchObject({
          issuer: `http://cognito.example.test:4566/${UserPoolId}`,
          jwks_uri: `http://cognito.example.test:4566/${UserPoolId}/.well-known/jwks.json`,
          token_endpoint: "http://cognito.example.test:4566/oauth2/token",
        });
      });
    },
    { config },
  ),
);

describe(
  "TokenConfig.IssuerFromRequest off",
  withCognitoSdk((Cognito, { serverUrl }) => {
    it("keeps the fixed IssuerDomain whatever the Host header", async () => {
      const client = Cognito();
      const pool = await client.createUserPool({ PoolName: "p" }).promise();
      const UserPoolId = pool.UserPool!.Id!;

      const discovery = await request(
        serverUrl(),
        `/${UserPoolId}/.well-known/openid-configuration`,
        "cognito.example.test:4566",
      );

      expect(discovery.body.issuer).toBe(
        `${DefaultConfig.TokenConfig.IssuerDomain}/${UserPoolId}`,
      );
    });
  }),
);
