import {
  AdminCreateUserCommand,
  AdminResetUserPasswordCommand,
  AdminSetUserPasswordCommand,
  CognitoIdentityProviderClient,
  ConfirmForgotPasswordCommand,
  ConfirmSignUpCommand,
  CreateUserPoolClientCommand,
  CreateUserPoolCommand,
  type CreateUserPoolCommandInput,
  ForgotPasswordCommand,
  InitiateAuthCommand,
  ResendConfirmationCodeCommand,
  SignUpCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "../aws-sdk/setup";

const PASSWORD = "Example-Passw0rd!";
const credentials = { accessKeyId: "local", secretAccessKey: "local" };

const newClient = (endpoint: string) =>
  new CognitoIdentityProviderClient({
    endpoint,
    region: "local",
    credentials,
    maxAttempts: 1,
  });

const setUp = async (
  cognito: CognitoIdentityProviderClient,
  pool: Partial<CreateUserPoolCommandInput> = {},
) => {
  const created = await cognito.send(
    new CreateUserPoolCommand({
      PoolName: "messages",
      AutoVerifiedAttributes: ["email"],
      ...pool,
    }),
  );
  const userPoolId = created.UserPool?.Id as string;
  const appClient = await cognito.send(
    new CreateUserPoolClientCommand({
      UserPoolId: userPoolId,
      ClientName: "messages",
      ExplicitAuthFlows: [
        "ALLOW_USER_PASSWORD_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
      ],
    }),
  );
  return { userPoolId, clientId: appClient.UserPoolClient?.ClientId as string };
};

describe(
  "Error messages",
  withCognitoSdk((_, { serverUrl, messageDelivery }) => {
    const lastCode = () =>
      messageDelivery().collectedMessages.at(-1)?.message.__code as string;

    it("uses Cognito's messages around sign-up confirmation", async () => {
      const cognito = newClient(serverUrl());
      const { clientId } = await setUp(cognito, {
        UsernameAttributes: ["email"],
      });
      await cognito.send(
        new SignUpCommand({
          ClientId: clientId,
          Username: "new@example.test",
          Password: PASSWORD,
        }),
      );

      await expect(
        cognito.send(
          new ConfirmSignUpCommand({
            ClientId: clientId,
            Username: "new@example.test",
            ConfirmationCode: "000000",
          }),
        ),
      ).rejects.toMatchObject({
        name: "CodeMismatchException",
        message: "Invalid verification code provided, please try again.",
      });
      await cognito.send(
        new ConfirmSignUpCommand({
          ClientId: clientId,
          Username: "new@example.test",
          ConfirmationCode: lastCode(),
        }),
      );
      await expect(
        cognito.send(
          new ConfirmSignUpCommand({
            ClientId: clientId,
            Username: "new@example.test",
            ConfirmationCode: lastCode(),
          }),
        ),
      ).rejects.toMatchObject({
        name: "NotAuthorizedException",
        message: "User cannot be confirmed. Current status is CONFIRMED",
      });
      await expect(
        cognito.send(
          new ResendConfirmationCodeCommand({
            ClientId: clientId,
            Username: "new@example.test",
          }),
        ),
      ).rejects.toMatchObject({
        name: "InvalidParameterException",
        message: "User is already confirmed.",
      });
      await expect(
        cognito.send(
          new SignUpCommand({
            ClientId: clientId,
            Username: "new@example.test",
            Password: PASSWORD,
          }),
        ),
      ).rejects.toMatchObject({
        name: "UsernameExistsException",
        message: "An account with the given email already exists.",
      });
    });

    it("names the phone number when a phone username is taken", async () => {
      const cognito = newClient(serverUrl());
      const { clientId } = await setUp(cognito, {
        UsernameAttributes: ["phone_number"],
        AutoVerifiedAttributes: ["phone_number"],
      });
      const signUp = () =>
        cognito.send(
          new SignUpCommand({
            ClientId: clientId,
            Username: "+15555550123",
            Password: PASSWORD,
            UserAttributes: [{ Name: "phone_number", Value: "+15555550123" }],
          }),
        );
      await signUp();
      await expect(signUp()).rejects.toMatchObject({
        name: "UsernameExistsException",
        message: "An account with the given phone_number already exists.",
      });
    });

    it("uses Cognito's messages around password reset", async () => {
      const cognito = newClient(serverUrl());
      const { userPoolId, clientId } = await setUp(cognito);
      await cognito.send(
        new AdminCreateUserCommand({
          UserPoolId: userPoolId,
          Username: "reset@example.test",
          TemporaryPassword: PASSWORD,
          MessageAction: "SUPPRESS",
          UserAttributes: [
            { Name: "email", Value: "reset@example.test" },
            { Name: "email_verified", Value: "true" },
          ],
        }),
      );

      await expect(
        cognito.send(
          new ForgotPasswordCommand({
            ClientId: clientId,
            Username: "reset@example.test",
          }),
        ),
      ).rejects.toMatchObject({
        name: "NotAuthorizedException",
        message: "User password cannot be reset in the current state.",
      });

      await cognito.send(
        new AdminSetUserPasswordCommand({
          UserPoolId: userPoolId,
          Username: "reset@example.test",
          Password: PASSWORD,
          Permanent: true,
        }),
      );
      await expect(
        cognito.send(
          new ConfirmForgotPasswordCommand({
            ClientId: clientId,
            Username: "reset@example.test",
            ConfirmationCode: "000000",
            Password: PASSWORD,
          }),
        ),
      ).rejects.toMatchObject({
        name: "ExpiredCodeException",
        message: "Invalid code provided, please request a code again.",
      });

      await cognito.send(
        new AdminResetUserPasswordCommand({
          UserPoolId: userPoolId,
          Username: "reset@example.test",
        }),
      );
      await expect(
        cognito.send(
          new InitiateAuthCommand({
            AuthFlow: "USER_PASSWORD_AUTH",
            ClientId: clientId,
            AuthParameters: { USERNAME: "reset@example.test", PASSWORD },
          }),
        ),
      ).rejects.toMatchObject({
        name: "PasswordResetRequiredException",
        message: "Password reset required for the user",
      });
      await expect(
        cognito.send(
          new ConfirmForgotPasswordCommand({
            ClientId: clientId,
            Username: "reset@example.test",
            ConfirmationCode: "000000",
            Password: PASSWORD,
          }),
        ),
      ).rejects.toMatchObject({
        name: "CodeMismatchException",
        message: "Invalid verification code provided, please try again.",
      });
    });
  }),
);
