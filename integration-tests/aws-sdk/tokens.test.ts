import { createHmac } from "node:crypto";
import type * as AWS from "aws-sdk";
import jwt from "jsonwebtoken";
import supertest from "supertest";
import { describe, expect, it } from "vitest";
import { ClockFake } from "../../src/__tests__/clockFake";
import { MockLogger } from "../../src/__tests__/mockLogger";
import PrivateKey from "../../src/keys/cognitoLocal.private.json";
import { DefaultConfig } from "../../src/server/config";
import type { User } from "../../src/services/userPoolService";
import { withCognitoSdk } from "./setup";

const PASSWORD = "Passw0rd!";
const MINUTE = 60 * 1000;

const secretHash = (username: string, clientId: string, secret: string) =>
  createHmac("sha256", secret)
    .update(username + clientId)
    .digest("base64");

const decode = (token: string) => jwt.decode(token) as Record<string, any>;

async function setupPool(
  client: AWS.CognitoIdentityServiceProvider,
  clientOverrides: Partial<AWS.CognitoIdentityServiceProvider.CreateUserPoolClientRequest> = {},
  poolOverrides: Partial<AWS.CognitoIdentityServiceProvider.CreateUserPoolRequest> = {},
  signInName = "alice",
) {
  const pool = await client
    .createUserPool({ PoolName: "tokens", ...poolOverrides })
    .promise();
  const UserPoolId = pool.UserPool!.Id!;
  const app = await client
    .createUserPoolClient({
      UserPoolId,
      ClientName: "app",
      ...clientOverrides,
    })
    .promise();
  const created = await client
    .adminCreateUser({
      UserPoolId,
      Username: signInName,
      MessageAction: "SUPPRESS",
      UserAttributes: [{ Name: "email", Value: "alice@example.test" }],
    })
    .promise();
  await client
    .adminSetUserPassword({
      UserPoolId,
      Username: signInName,
      Password: PASSWORD,
      Permanent: true,
    })
    .promise();
  const sub = created.User!.Attributes!.find((a) => a.Name === "sub")!.Value!;
  return {
    UserPoolId,
    ClientId: app.UserPoolClient!.ClientId!,
    ClientSecret: app.UserPoolClient!.ClientSecret,
    username: created.User!.Username!,
    sub,
  };
}

const login = (
  client: AWS.CognitoIdentityServiceProvider,
  ClientId: string,
  extra: Record<string, string> = {},
) =>
  client
    .initiateAuth({
      ClientId,
      AuthFlow: "USER_PASSWORD_AUTH",
      AuthParameters: { USERNAME: "alice", PASSWORD, ...extra },
    })
    .promise();

const refresh = (
  client: AWS.CognitoIdentityServiceProvider,
  ClientId: string,
  REFRESH_TOKEN: string,
  extra: Record<string, string> = {},
) =>
  client
    .initiateAuth({
      ClientId,
      AuthFlow: "REFRESH_TOKEN_AUTH",
      AuthParameters: { REFRESH_TOKEN, ...extra },
    })
    .promise();

const getUser = (client: AWS.CognitoIdentityServiceProvider, token: string) =>
  client.getUser({ AccessToken: token }).promise();

const notAuthorized = (message: string) =>
  expect.objectContaining({ code: "NotAuthorizedException", message });

const clock = new ClockFake(new Date());

describe(
  "Access and refresh tokens",
  withCognitoSdk(
    (Cognito, { serverUrl, dataStoreFactory }) => {
      it("accepts a token it issued", async () => {
        const client = Cognito();
        const { ClientId } = await setupPool(client);
        const auth = await login(client, ClientId);

        const me = await getUser(
          client,
          auth.AuthenticationResult!.AccessToken!,
        );

        expect(me.Username).toEqual("alice");
        expect(auth.AuthenticationResult?.ExpiresIn).toEqual(3600);
        expect(auth.AuthenticationResult?.TokenType).toEqual("Bearer");
      });

      it("rejects a garbage token as an invalid access token", async () => {
        const client = Cognito();
        await setupPool(client);

        await expect(getUser(client, "not-a-jwt")).rejects.toEqual(
          notAuthorized("Invalid Access Token"),
        );
      });

      it("rejects a token signed with another key", async () => {
        const client = Cognito();
        const { ClientId } = await setupPool(client);
        const auth = await login(client, ClientId);
        const claims = decode(auth.AuthenticationResult!.AccessToken!);
        const { exp: _exp, iat: _iat, ...unsigned } = claims;
        const forged = jwt.sign(unsigned, "a-different-secret", {
          algorithm: "HS256",
          expiresIn: 3600,
        });

        await expect(getUser(client, forged)).rejects.toEqual(
          notAuthorized("Invalid Access Token"),
        );
      });

      it("rejects an ID token and a token from an unknown issuer", async () => {
        const client = Cognito();
        const { ClientId } = await setupPool(client);
        const auth = await login(client, ClientId);
        const claims = decode(auth.AuthenticationResult!.AccessToken!);
        const otherIssuer = jwt.sign(
          { ...claims, iss: "http://elsewhere.test/pool" },
          PrivateKey.pem,
          { algorithm: "RS256", keyid: "CognitoLocal" },
        );

        await expect(
          getUser(client, auth.AuthenticationResult!.IdToken!),
        ).rejects.toEqual(notAuthorized("Invalid Access Token"));
        await expect(getUser(client, otherIssuer)).rejects.toEqual(
          notAuthorized("Invalid Access Token"),
        );
      });

      it("rejects an expired access token", async () => {
        const client = Cognito();
        const { ClientId } = await setupPool(client);
        const auth = await login(client, ClientId);

        clock.advanceBy(60 * MINUTE + 1000);

        await expect(
          getUser(client, auth.AuthenticationResult!.AccessToken!),
        ).rejects.toEqual(notAuthorized("Access Token has expired"));
      });

      it("revokes every token on GlobalSignOut, and a new sign-in works at once", async () => {
        const client = Cognito();
        const { ClientId } = await setupPool(client);
        const first = await login(client, ClientId);
        const second = await login(client, ClientId);

        await client
          .globalSignOut({
            AccessToken: first.AuthenticationResult!.AccessToken!,
          })
          .promise();

        for (const auth of [first, second]) {
          await expect(
            getUser(client, auth.AuthenticationResult!.AccessToken!),
          ).rejects.toEqual(notAuthorized("Access Token has been revoked"));
          await expect(
            refresh(client, ClientId, auth.AuthenticationResult!.RefreshToken!),
          ).rejects.toEqual(notAuthorized("Refresh Token has been revoked"));
        }

        const again = await login(client, ClientId);
        await expect(
          getUser(client, again.AuthenticationResult!.AccessToken!),
        ).resolves.toMatchObject({ Username: "alice" });
      });

      it("revokes every token on AdminUserGlobalSignOut", async () => {
        const client = Cognito();
        const { ClientId, UserPoolId } = await setupPool(client);
        const auth = await login(client, ClientId);

        await client
          .adminUserGlobalSignOut({ UserPoolId, Username: "alice" })
          .promise();

        await expect(
          getUser(client, auth.AuthenticationResult!.AccessToken!),
        ).rejects.toEqual(notAuthorized("Access Token has been revoked"));
      });

      it("writes the revocation to the pool's data file", async () => {
        const client = Cognito();
        const { ClientId, UserPoolId } = await setupPool(client);
        const auth = await login(client, ClientId);
        const freshRead = async () => {
          const store = await dataStoreFactory().create(
            { logger: MockLogger as any },
            UserPoolId,
            {},
          );
          return store.get<User>({ logger: MockLogger as any }, [
            "Users",
            "alice",
          ]);
        };
        expect((await freshRead())?.TokenOrigins).toHaveLength(1);

        await client
          .globalSignOut({
            AccessToken: auth.AuthenticationResult!.AccessToken!,
          })
          .promise();

        expect(await freshRead()).toMatchObject({
          RefreshTokens: [],
          TokenOrigins: [],
        });
      });

      it("RevokeToken revokes the refresh token and its access tokens only", async () => {
        const client = Cognito();
        const { ClientId } = await setupPool(client);
        const revoked = await login(client, ClientId);
        const kept = await login(client, ClientId);
        const refreshed = await refresh(
          client,
          ClientId,
          revoked.AuthenticationResult!.RefreshToken!,
        );

        await client
          .revokeToken({
            ClientId,
            Token: revoked.AuthenticationResult!.RefreshToken!,
          })
          .promise();

        for (const token of [
          revoked.AuthenticationResult!.AccessToken!,
          refreshed.AuthenticationResult!.AccessToken!,
        ]) {
          await expect(getUser(client, token)).rejects.toEqual(
            notAuthorized("Access Token has been revoked"),
          );
        }
        await expect(
          refresh(
            client,
            ClientId,
            revoked.AuthenticationResult!.RefreshToken!,
          ),
        ).rejects.toEqual(notAuthorized("Refresh Token has been revoked"));
        await expect(
          getUser(client, kept.AuthenticationResult!.AccessToken!),
        ).resolves.toMatchObject({ Username: "alice" });
      });

      it("RevokeToken is refused when the client has token revocation disabled", async () => {
        const client = Cognito();
        const { ClientId } = await setupPool(client, {
          EnableTokenRevocation: false,
        });
        const auth = await login(client, ClientId);

        await expect(
          client
            .revokeToken({
              ClientId,
              Token: auth.AuthenticationResult!.RefreshToken!,
            })
            .promise(),
        ).rejects.toMatchObject({ code: "UnsupportedOperationException" });
      });

      it("disabling a user revokes its tokens, also after enabling it again", async () => {
        const client = Cognito();
        const { ClientId, UserPoolId } = await setupPool(client);
        const auth = await login(client, ClientId);
        const token = auth.AuthenticationResult!.AccessToken!;

        await client
          .adminDisableUser({ UserPoolId, Username: "alice" })
          .promise();
        await expect(getUser(client, token)).rejects.toEqual(
          notAuthorized("User is disabled."),
        );

        await client
          .adminEnableUser({ UserPoolId, Username: "alice" })
          .promise();
        await expect(getUser(client, token)).rejects.toEqual(
          notAuthorized("Access Token has been revoked"),
        );
      });

      it("a deleted user's token no longer works", async () => {
        const client = Cognito();
        const { ClientId, UserPoolId } = await setupPool(client);
        const auth = await login(client, ClientId);

        await client
          .adminDeleteUser({ UserPoolId, Username: "alice" })
          .promise();

        await expect(
          getUser(client, auth.AuthenticationResult!.AccessToken!),
        ).rejects.toMatchObject({
          code: "UserNotFoundException",
          message: "User does not exist.",
        });
      });

      it("honours the client's token validity and units in every flow", async () => {
        const client = Cognito();
        const { ClientId } = await setupPool(client, {
          AccessTokenValidity: 10,
          IdTokenValidity: 2,
          RefreshTokenValidity: 60,
          TokenValidityUnits: {
            AccessToken: "minutes",
            IdToken: "hours",
            RefreshToken: "minutes",
          },
        });
        const auth = await login(client, ClientId);
        const now = Math.floor(clock.get().getTime() / 1000);

        expect(auth.AuthenticationResult?.ExpiresIn).toEqual(600);
        expect(decode(auth.AuthenticationResult!.AccessToken!).exp).toEqual(
          now + 600,
        );
        expect(decode(auth.AuthenticationResult!.IdToken!).exp).toEqual(
          now + 7200,
        );
        expect(decode(auth.AuthenticationResult!.RefreshToken!).exp).toEqual(
          now + 3600,
        );

        const refreshed = await refresh(
          client,
          ClientId,
          auth.AuthenticationResult!.RefreshToken!,
        );
        expect(refreshed.AuthenticationResult?.ExpiresIn).toEqual(600);

        clock.advanceBy(61 * MINUTE);
        await expect(
          refresh(client, ClientId, auth.AuthenticationResult!.RefreshToken!),
        ).rejects.toEqual(notAuthorized("Refresh Token has expired"));
      });

      it("the token endpoint honours the access token validity", async () => {
        const client = Cognito();
        const { ClientId } = await setupPool(client, {
          AccessTokenValidity: 30,
          TokenValidityUnits: { AccessToken: "minutes" },
        });
        const auth = await login(client, ClientId);

        const res = await supertest(serverUrl())
          .post("/oauth2/token")
          .type("form")
          .send({
            grant_type: "refresh_token",
            client_id: ClientId,
            refresh_token: auth.AuthenticationResult!.RefreshToken!,
          });

        expect(res.status).toEqual(200);
        expect(res.body.expires_in).toEqual(1800);
      });

      it("the userInfo endpoint rejects a revoked access token", async () => {
        const client = Cognito();
        const { ClientId } = await setupPool(client);
        const auth = await login(client, ClientId);
        const token = auth.AuthenticationResult!.AccessToken!;

        const ok = await supertest(serverUrl())
          .get("/oauth2/userInfo")
          .set("Authorization", `Bearer ${token}`);
        expect(ok.status).toEqual(200);

        await client.globalSignOut({ AccessToken: token }).promise();
        const revoked = await supertest(serverUrl())
          .get("/oauth2/userInfo")
          .set("Authorization", `Bearer ${token}`);
        expect(revoked.status).toEqual(401);
        expect(revoked.body).toEqual({
          error: "invalid_token",
          error_description: "Access token has been revoked",
        });
      });

      describe("SECRET_HASH", () => {
        it("is required from a client with a secret", async () => {
          const client = Cognito();
          const { ClientId } = await setupPool(client, {
            GenerateSecret: true,
          });

          await expect(login(client, ClientId)).rejects.toEqual(
            notAuthorized(
              `Client ${ClientId} is configured for secret but secret was not received`,
            ),
          );
        });

        it("must match the username and client id", async () => {
          const client = Cognito();
          const { ClientId, ClientSecret } = await setupPool(client, {
            GenerateSecret: true,
          });

          await expect(
            login(client, ClientId, {
              SECRET_HASH: secretHash("bob", ClientId, ClientSecret!),
            }),
          ).rejects.toEqual(
            notAuthorized(
              `Unable to verify secret hash for client ${ClientId}`,
            ),
          );

          const auth = await login(client, ClientId, {
            SECRET_HASH: secretHash("alice", ClientId, ClientSecret!),
          });
          expect(auth.AuthenticationResult?.AccessToken).toBeDefined();
        });

        it("uses the username for REFRESH_TOKEN_AUTH when username is a sign-in attribute", async () => {
          const client = Cognito();
          const { ClientId, ClientSecret, sub } = await setupPool(client, {
            GenerateSecret: true,
          });
          const auth = await login(client, ClientId, {
            SECRET_HASH: secretHash("alice", ClientId, ClientSecret!),
          });
          const token = auth.AuthenticationResult!.RefreshToken!;

          await expect(
            refresh(client, ClientId, token, {
              SECRET_HASH: secretHash(sub, ClientId, ClientSecret!),
            }),
          ).rejects.toMatchObject({ code: "NotAuthorizedException" });
          await expect(
            refresh(client, ClientId, token, {
              SECRET_HASH: secretHash("alice", ClientId, ClientSecret!),
            }),
          ).resolves.toBeDefined();
        });

        it("uses the sub for REFRESH_TOKEN_AUTH when the pool signs in with email", async () => {
          const client = Cognito();
          const { ClientId, ClientSecret, sub } = await setupPool(
            client,
            { GenerateSecret: true },
            { UsernameAttributes: ["email"] },
            "alice@example.test",
          );
          const auth = await client
            .initiateAuth({
              ClientId,
              AuthFlow: "USER_PASSWORD_AUTH",
              AuthParameters: {
                USERNAME: "alice@example.test",
                PASSWORD,
                SECRET_HASH: secretHash(
                  "alice@example.test",
                  ClientId,
                  ClientSecret!,
                ),
              },
            })
            .promise();

          await expect(
            refresh(
              client,
              ClientId,
              auth.AuthenticationResult!.RefreshToken!,
              {
                SECRET_HASH: secretHash(sub, ClientId, ClientSecret!),
              },
            ),
          ).resolves.toBeDefined();
        });

        it("is checked on SignUp and the other SecretHash operations", async () => {
          const client = Cognito();
          const { ClientId, ClientSecret } = await setupPool(client, {
            GenerateSecret: true,
          });

          await expect(
            client
              .signUp({ ClientId, Username: "carol", Password: PASSWORD })
              .promise(),
          ).rejects.toEqual(
            notAuthorized(
              `Client ${ClientId} is configured for secret but secret was not received`,
            ),
          );
          await expect(
            client
              .forgotPassword({
                ClientId,
                Username: "alice",
                SecretHash: secretHash("carol", ClientId, ClientSecret!),
              })
              .promise(),
          ).rejects.toEqual(
            notAuthorized(
              `Unable to verify secret hash for client ${ClientId}`,
            ),
          );
          await expect(
            client
              .signUp({
                ClientId,
                Username: "carol",
                Password: PASSWORD,
                SecretHash: secretHash("carol", ClientId, ClientSecret!),
              })
              .promise(),
          ).resolves.toMatchObject({ UserConfirmed: false });
        });
      });
    },
    { clock },
  ),
);

describe(
  "Lenient token handling (TokenConfig.Verify and CheckSecretHash off)",
  withCognitoSdk(
    (Cognito) => {
      it("decodes access tokens without checking them, as before", async () => {
        const client = Cognito();
        const { ClientId } = await setupPool(client, { GenerateSecret: true });
        const auth = await login(client, ClientId);
        await client
          .globalSignOut({
            AccessToken: auth.AuthenticationResult!.AccessToken!,
          })
          .promise();

        await expect(
          getUser(client, auth.AuthenticationResult!.AccessToken!),
        ).resolves.toMatchObject({ Username: "alice" });
        await expect(getUser(client, "not-a-jwt")).rejects.toMatchObject({
          code: "InvalidParameterException",
        });
      });
    },
    {
      config: {
        ...DefaultConfig,
        TokenConfig: {
          ...DefaultConfig.TokenConfig,
          Verify: false,
          CheckSecretHash: false,
        },
      },
    },
  ),
);
