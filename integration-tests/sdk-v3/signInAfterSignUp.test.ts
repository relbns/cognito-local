import {
  AdminInitiateAuthCommand,
  CognitoIdentityProviderClient,
  ConfirmSignUpCommand,
  CreateUserPoolClientCommand,
  CreateUserPoolCommand,
  type ExplicitAuthFlowsType,
  InitiateAuthCommand,
  SignUpCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "../aws-sdk/setup";

const PASSWORD = "Example-Passw0rd!";
const EMAIL = "new-user@example.test";
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
  flows: ExplicitAuthFlowsType[],
) => {
  const created = await cognito.send(
    new CreateUserPoolCommand({
      PoolName: "sign-up-session",
      UsernameAttributes: ["email"],
      AutoVerifiedAttributes: ["email"],
      Policies: {
        SignInPolicy: { AllowedFirstAuthFactors: ["PASSWORD", "EMAIL_OTP"] },
      },
    }),
  );
  const userPoolId = created.UserPool?.Id as string;
  const appClient = await cognito.send(
    new CreateUserPoolClientCommand({
      UserPoolId: userPoolId,
      ClientName: "sign-up-session",
      ExplicitAuthFlows: flows,
    }),
  );
  return { userPoolId, clientId: appClient.UserPoolClient?.ClientId as string };
};

describe(
  "Sign-in after sign-up with the ConfirmSignUp Session",
  withCognitoSdk((_, { serverUrl, messageDelivery }) => {
    const lastCode = () =>
      messageDelivery().collectedMessages.at(-1)?.message.__code as string;

    it("signs the confirmed user in with USER_AUTH and the Session, once", async () => {
      const cognito = newClient(serverUrl());
      const { userPoolId, clientId } = await setUp(cognito, [
        "ALLOW_USER_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
      ]);

      const signedUp = await cognito.send(
        new SignUpCommand({
          ClientId: clientId,
          Username: EMAIL,
          Password: PASSWORD,
        }),
      );
      expect(signedUp.Session).toEqual(expect.any(String));

      const confirmed = await cognito.send(
        new ConfirmSignUpCommand({
          ClientId: clientId,
          Username: EMAIL,
          ConfirmationCode: lastCode(),
          Session: signedUp.Session,
        }),
      );
      expect(confirmed.Session).toEqual(expect.any(String));

      const signedIn = await cognito.send(
        new InitiateAuthCommand({
          AuthFlow: "USER_AUTH",
          ClientId: clientId,
          AuthParameters: { USERNAME: EMAIL },
          Session: confirmed.Session,
        }),
      );
      expect(signedIn.AuthenticationResult?.AccessToken).toBeDefined();
      expect(signedIn.ChallengeName).toBeUndefined();

      await expect(
        cognito.send(
          new AdminInitiateAuthCommand({
            AuthFlow: "USER_AUTH",
            UserPoolId: userPoolId,
            ClientId: clientId,
            AuthParameters: { USERNAME: EMAIL },
            Session: confirmed.Session,
          }),
        ),
      ).rejects.toMatchObject({
        name: "NotAuthorizedException",
        message: "Invalid session for the user.",
      });
    });

    it("refuses a Session that is not from ConfirmSignUp of that user", async () => {
      const cognito = newClient(serverUrl());
      const { clientId } = await setUp(cognito, ["ALLOW_USER_AUTH"]);
      const signedUp = await cognito.send(
        new SignUpCommand({
          ClientId: clientId,
          Username: EMAIL,
          Password: PASSWORD,
        }),
      );
      await cognito.send(
        new ConfirmSignUpCommand({
          ClientId: clientId,
          Username: EMAIL,
          ConfirmationCode: lastCode(),
        }),
      );

      await expect(
        cognito.send(
          new InitiateAuthCommand({
            AuthFlow: "USER_AUTH",
            ClientId: clientId,
            AuthParameters: { USERNAME: EMAIL },
            Session: signedUp.Session,
          }),
        ),
      ).rejects.toMatchObject({ name: "NotAuthorizedException" });
    });

    it("returns no Session to a client without ALLOW_USER_AUTH", async () => {
      const cognito = newClient(serverUrl());
      const { clientId } = await setUp(cognito, [
        "ALLOW_USER_PASSWORD_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
      ]);
      const signedUp = await cognito.send(
        new SignUpCommand({
          ClientId: clientId,
          Username: EMAIL,
          Password: PASSWORD,
        }),
      );
      expect(signedUp.Session).toBeUndefined();
      const confirmed = await cognito.send(
        new ConfirmSignUpCommand({
          ClientId: clientId,
          Username: EMAIL,
          ConfirmationCode: lastCode(),
        }),
      );
      expect(confirmed.Session).toBeUndefined();
    });
  }),
);
