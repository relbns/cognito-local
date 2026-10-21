import { createHmac } from "node:crypto";
import {
  AddUserPoolClientSecretCommand,
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  CognitoIdentityProviderClient,
  CreateUserPoolClientCommand,
  CreateUserPoolCommand,
  DeleteUserPoolClientSecretCommand,
  InitiateAuthCommand,
  ListUserPoolClientSecretsCommand,
  NotAuthorizedException,
  ResourceNotFoundException,
} from "@aws-sdk/client-cognito-identity-provider";
import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "../aws-sdk/setup";

const PASSWORD = "Example-Passw0rd!";
const USERNAME = "secret-user";
const credentials = { accessKeyId: "local", secretAccessKey: "local" };

const secretHash = (clientId: string, secret: string) =>
  createHmac("sha256", secret)
    .update(`${USERNAME}${clientId}`)
    .digest("base64");

describe(
  "App client secrets",
  withCognitoSdk((_, { serverUrl }) => {
    const setUp = async (GenerateSecret: boolean) => {
      const cognito = new CognitoIdentityProviderClient({
        endpoint: serverUrl(),
        region: "local",
        credentials,
        maxAttempts: 1,
      });
      const pool = await cognito.send(
        new CreateUserPoolCommand({
          PoolName: "secrets",
          UsernameAttributes: [],
        }),
      );
      const userPoolId = pool.UserPool?.Id as string;
      const client = await cognito.send(
        new CreateUserPoolClientCommand({
          UserPoolId: userPoolId,
          ClientName: "backend",
          GenerateSecret,
          ExplicitAuthFlows: ["ALLOW_USER_PASSWORD_AUTH"],
        }),
      );
      await cognito.send(
        new AdminCreateUserCommand({
          UserPoolId: userPoolId,
          Username: USERNAME,
          MessageAction: "SUPPRESS",
        }),
      );
      await cognito.send(
        new AdminSetUserPasswordCommand({
          UserPoolId: userPoolId,
          Username: USERNAME,
          Password: PASSWORD,
          Permanent: true,
        }),
      );
      const clientId = client.UserPoolClient?.ClientId as string;
      const signIn = (secret?: string) =>
        cognito.send(
          new InitiateAuthCommand({
            AuthFlow: "USER_PASSWORD_AUTH",
            ClientId: clientId,
            AuthParameters: {
              USERNAME,
              PASSWORD,
              ...(secret && { SECRET_HASH: secretHash(clientId, secret) }),
            },
          }),
        );
      return {
        cognito,
        userPoolId,
        clientId,
        originalSecret: client.UserPoolClient?.ClientSecret,
        signIn,
      };
    };

    it("lists the secret made with the client, without its value", async () => {
      const { cognito, userPoolId, clientId } = await setUp(true);

      const listed = await cognito.send(
        new ListUserPoolClientSecretsCommand({
          UserPoolId: userPoolId,
          ClientId: clientId,
        }),
      );

      expect(listed.ClientSecrets).toEqual([
        {
          ClientSecretId: expect.stringMatching(
            new RegExp(`^${clientId}--\\d+$`),
          ),
          ClientSecretCreateDate: expect.any(Date),
        },
      ]);
    });

    it("signs in with a secret added to a public client, and refuses the request without it", async () => {
      const { cognito, userPoolId, clientId, signIn } = await setUp(false);
      await expect(signIn()).resolves.toHaveProperty("AuthenticationResult");

      const added = await cognito.send(
        new AddUserPoolClientSecretCommand({
          UserPoolId: userPoolId,
          ClientId: clientId,
        }),
      );
      const secret = added.ClientSecretDescriptor?.ClientSecretValue as string;

      expect(added.ClientSecretDescriptor).toEqual({
        ClientSecretId: expect.stringMatching(
          new RegExp(`^${clientId}--\\d+$`),
        ),
        ClientSecretValue: expect.stringMatching(/^[0-9a-z]+$/),
        ClientSecretCreateDate: expect.any(Date),
      });
      await expect(signIn(secret)).resolves.toHaveProperty(
        "AuthenticationResult",
      );
      await expect(signIn()).rejects.toBeInstanceOf(NotAuthorizedException);
    });

    it("replaces the client's secret with the one given", async () => {
      const { cognito, userPoolId, clientId, originalSecret, signIn } =
        await setUp(true);
      const chosen = "examplechosensecret0000000000000000000000000001";

      const added = await cognito.send(
        new AddUserPoolClientSecretCommand({
          UserPoolId: userPoolId,
          ClientId: clientId,
          ClientSecret: chosen,
        }),
      );

      expect(added.ClientSecretDescriptor?.ClientSecretValue).toBe(chosen);
      await expect(signIn(chosen)).resolves.toHaveProperty(
        "AuthenticationResult",
      );
      await expect(signIn(originalSecret)).rejects.toBeInstanceOf(
        NotAuthorizedException,
      );
    });

    it("deletes the secret by its id, which makes the client public", async () => {
      const { cognito, userPoolId, clientId, signIn } = await setUp(true);
      const [current] =
        (
          await cognito.send(
            new ListUserPoolClientSecretsCommand({
              UserPoolId: userPoolId,
              ClientId: clientId,
            }),
          )
        ).ClientSecrets ?? [];

      await expect(
        cognito.send(
          new DeleteUserPoolClientSecretCommand({
            UserPoolId: userPoolId,
            ClientId: clientId,
            ClientSecretId: `${clientId}--1`,
          }),
        ),
      ).rejects.toBeInstanceOf(ResourceNotFoundException);
      await cognito.send(
        new DeleteUserPoolClientSecretCommand({
          UserPoolId: userPoolId,
          ClientId: clientId,
          ClientSecretId: current.ClientSecretId,
        }),
      );

      const listed = await cognito.send(
        new ListUserPoolClientSecretsCommand({
          UserPoolId: userPoolId,
          ClientId: clientId,
        }),
      );
      expect(listed.ClientSecrets).toEqual([]);
      await expect(signIn()).resolves.toHaveProperty("AuthenticationResult");
    });

    it("refuses a client of another pool", async () => {
      const first = await setUp(true);
      const second = await setUp(true);

      await expect(
        first.cognito.send(
          new AddUserPoolClientSecretCommand({
            UserPoolId: first.userPoolId,
            ClientId: second.clientId,
          }),
        ),
      ).rejects.toBeInstanceOf(ResourceNotFoundException);
    });
  }),
);
