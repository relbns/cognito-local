import {
  AdminCreateUserCommand,
  AdminInitiateAuthCommand,
  AdminSetUserPasswordCommand,
  CognitoIdentityProviderClient,
  ConfirmForgotPasswordCommand,
  CreateUserPoolClientCommand,
  CreateUserPoolCommand,
  ForgotPasswordCommand,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { describe, expect, it } from "vitest";
import { ClockFake } from "../../src/__tests__/clockFake";
import { srpClient } from "../../src/__tests__/srpClient";
import { type Config, DefaultConfig } from "../../src/server/config";
import { withCognitoSdk } from "../aws-sdk/setup";

const PASSWORD = "Example-Passw0rd!";
const USERNAME = "locked@example.test";
const credentials = { accessKeyId: "local", secretAccessKey: "local" };

const newClient = (endpoint: string) =>
  new CognitoIdentityProviderClient({
    endpoint,
    region: "local",
    credentials,
    maxAttempts: 1,
  });

const setUp = async (cognito: CognitoIdentityProviderClient) => {
  const created = await cognito.send(
    new CreateUserPoolCommand({ PoolName: "lockout" }),
  );
  const userPoolId = created.UserPool?.Id as string;
  const appClient = await cognito.send(
    new CreateUserPoolClientCommand({
      UserPoolId: userPoolId,
      ClientName: "lockout",
      ExplicitAuthFlows: [
        "ALLOW_USER_PASSWORD_AUTH",
        "ALLOW_USER_SRP_AUTH",
        "ALLOW_ADMIN_USER_PASSWORD_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
      ],
    }),
  );
  await cognito.send(
    new AdminCreateUserCommand({
      UserPoolId: userPoolId,
      Username: USERNAME,
      MessageAction: "SUPPRESS",
      UserAttributes: [
        { Name: "email", Value: USERNAME },
        { Name: "email_verified", Value: "true" },
      ],
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
  return { userPoolId, clientId: appClient.UserPoolClient?.ClientId as string };
};

const signIn = (
  cognito: CognitoIdentityProviderClient,
  clientId: string,
  password: string,
) =>
  cognito.send(
    new InitiateAuthCommand({
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: clientId,
      AuthParameters: { USERNAME, PASSWORD: password },
    }),
  );

const incorrect = {
  name: "NotAuthorizedException",
  message: "Incorrect username or password.",
};
const exceeded = {
  name: "NotAuthorizedException",
  message: "Password attempts exceeded",
};

const clock = new ClockFake(new Date("2026-10-21T10:00:00Z"));

describe(
  "Sign-in lockout",
  withCognitoSdk(
    (_, { serverUrl }) => {
      it("locks out after five wrong passwords for 2^(n-5) seconds", async () => {
        const cognito = newClient(serverUrl());
        const { clientId } = await setUp(cognito);

        for (let i = 0; i < 5; i++) {
          await expect(
            signIn(cognito, clientId, "wrong"),
          ).rejects.toMatchObject(incorrect);
        }
        await expect(signIn(cognito, clientId, PASSWORD)).rejects.toMatchObject(
          exceeded,
        );

        clock.advanceBy(1000);
        await expect(signIn(cognito, clientId, "wrong")).rejects.toMatchObject(
          incorrect,
        );
        clock.advanceBy(1999);
        await expect(signIn(cognito, clientId, PASSWORD)).rejects.toMatchObject(
          exceeded,
        );
        clock.advanceBy(1);
        const signedIn = await signIn(cognito, clientId, PASSWORD);
        expect(signedIn.AuthenticationResult?.AccessToken).toBeDefined();

        for (let i = 0; i < 4; i++) {
          await expect(
            signIn(cognito, clientId, "wrong"),
          ).rejects.toMatchObject(incorrect);
        }
        expect(
          (await signIn(cognito, clientId, PASSWORD)).AuthenticationResult,
        ).toBeDefined();
      });

      it("counts admin and SRP failures and forgets them after 15 quiet minutes", async () => {
        const cognito = newClient(serverUrl());
        const { userPoolId, clientId } = await setUp(cognito);

        for (let i = 0; i < 4; i++) {
          await expect(
            cognito.send(
              new AdminInitiateAuthCommand({
                AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
                UserPoolId: userPoolId,
                ClientId: clientId,
                AuthParameters: { USERNAME, PASSWORD: "wrong" },
              }),
            ),
          ).rejects.toMatchObject(incorrect);
        }
        const srp = srpClient(userPoolId);
        const challenge = await cognito.send(
          new InitiateAuthCommand({
            AuthFlow: "USER_SRP_AUTH",
            ClientId: clientId,
            AuthParameters: { USERNAME, SRP_A: srp.srpA },
          }),
        );
        await expect(
          cognito.send(
            new RespondToAuthChallengeCommand({
              ClientId: clientId,
              ChallengeName: "PASSWORD_VERIFIER",
              Session: challenge.Session,
              ChallengeResponses: srp.respond(
                challenge.ChallengeParameters ?? {},
                "wrong",
              ),
            }),
          ),
        ).rejects.toMatchObject(incorrect);
        await expect(signIn(cognito, clientId, PASSWORD)).rejects.toMatchObject(
          exceeded,
        );

        clock.advanceBy(15 * 60_000);
        await expect(signIn(cognito, clientId, "wrong")).rejects.toMatchObject(
          incorrect,
        );
        expect(
          (await signIn(cognito, clientId, PASSWORD)).AuthenticationResult,
        ).toBeDefined();
      });

      it("limits password reset attempts per hour", async () => {
        const cognito = newClient(serverUrl());
        const { clientId } = await setUp(cognito);

        await cognito.send(
          new ForgotPasswordCommand({ ClientId: clientId, Username: USERNAME }),
        );
        await expect(
          cognito.send(
            new ConfirmForgotPasswordCommand({
              ClientId: clientId,
              Username: USERNAME,
              ConfirmationCode: "000000",
              Password: PASSWORD,
            }),
          ),
        ).rejects.toMatchObject({ name: "CodeMismatchException" });
        await cognito.send(
          new ForgotPasswordCommand({ ClientId: clientId, Username: USERNAME }),
        );
        await expect(
          cognito.send(
            new ForgotPasswordCommand({
              ClientId: clientId,
              Username: USERNAME,
            }),
          ),
        ).rejects.toMatchObject({
          name: "LimitExceededException",
          message: "Attempt limit exceeded, please try after some time.",
        });

        clock.advanceBy(60 * 60_000);
        await cognito.send(
          new ForgotPasswordCommand({ ClientId: clientId, Username: USERNAME }),
        );
      });
    },
    {
      clock,
      config: {
        ...DefaultConfig,
        LockoutConfig: { Enabled: true, PasswordResetAttemptsPerHour: 3 },
      } satisfies Config,
    },
  ),
);

describe(
  "Sign-in lockout switched off",
  withCognitoSdk(
    (_, { serverUrl }) => {
      it("never locks a user out", async () => {
        const cognito = newClient(serverUrl());
        const { clientId } = await setUp(cognito);
        for (let i = 0; i < 8; i++) {
          await expect(
            signIn(cognito, clientId, "wrong"),
          ).rejects.toMatchObject(incorrect);
        }
        expect(
          (await signIn(cognito, clientId, PASSWORD)).AuthenticationResult,
        ).toBeDefined();
      });
    },
    {
      config: {
        ...DefaultConfig,
        LockoutConfig: { Enabled: false, PasswordResetAttemptsPerHour: 20 },
      } satisfies Config,
    },
  ),
);
