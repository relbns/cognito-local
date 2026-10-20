import type { CognitoIdentityServiceProvider } from "aws-sdk";
import { describe, expect, it } from "vitest";
import { DefaultConfig } from "../../src/server/config";
import { withCognitoSdk } from "./setup";

const STRONG = "Passw0rd!";

const setup = async (
  client: CognitoIdentityServiceProvider,
  Policies?: CognitoIdentityServiceProvider.UserPoolPolicyType,
) => {
  const pool = await client
    .createUserPool({ PoolName: "test", UsernameAttributes: [], Policies })
    .promise();
  const userPoolId = pool.UserPool?.Id as string;
  const upc = await client
    .createUserPoolClient({ UserPoolId: userPoolId, ClientName: "app" })
    .promise();
  return { userPoolId, clientId: upc.UserPoolClient?.ClientId as string };
};

const signIn = async (
  client: CognitoIdentityServiceProvider,
  clientId: string,
  username: string,
  password: string,
) =>
  client
    .initiateAuth({
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: clientId,
      AuthParameters: { USERNAME: username, PASSWORD: password },
    })
    .promise();

describe(
  "CognitoIdentityServiceProvider password policy",
  withCognitoSdk((Cognito, { messageDelivery }) => {
    it("applies the AWS default policy to a new pool", async () => {
      const client = Cognito();
      const { userPoolId } = await setup(client);

      const pool = await client
        .describeUserPool({ UserPoolId: userPoolId })
        .promise();

      expect(pool.UserPool?.Policies?.PasswordPolicy).toEqual({
        MinimumLength: 8,
        RequireUppercase: true,
        RequireLowercase: true,
        RequireNumbers: true,
        RequireSymbols: true,
        TemporaryPasswordValidityDays: 7,
      });
    });

    it("rejects a weak SignUp password", async () => {
      const client = Cognito();
      const { clientId } = await setup(client);

      await expect(
        client
          .signUp({ ClientId: clientId, Username: "jane", Password: "short" })
          .promise(),
      ).rejects.toMatchObject({
        code: "InvalidPasswordException",
        message:
          "Password did not conform with policy: Password not long enough",
      });
    });

    it("applies only the requirements a custom policy sets", async () => {
      const client = Cognito();
      const { clientId } = await setup(client, {
        PasswordPolicy: { MinimumLength: 6 },
      });

      await client
        .signUp({ ClientId: clientId, Username: "jane", Password: "abcdef" })
        .promise();
      await expect(
        client
          .signUp({ ClientId: clientId, Username: "joe", Password: "abcde" })
          .promise(),
      ).rejects.toMatchObject({ code: "InvalidPasswordException" });
    });

    it("rejects a weak TemporaryPassword and AdminSetUserPassword", async () => {
      const client = Cognito();
      const { userPoolId } = await setup(client);

      await expect(
        client
          .adminCreateUser({
            UserPoolId: userPoolId,
            Username: "jane",
            MessageAction: "SUPPRESS",
            TemporaryPassword: "password1!",
          })
          .promise(),
      ).rejects.toMatchObject({
        code: "InvalidPasswordException",
        message:
          "Password does not conform to policy: Password must have uppercase characters",
      });

      await client
        .adminCreateUser({
          UserPoolId: userPoolId,
          Username: "jane",
          MessageAction: "SUPPRESS",
        })
        .promise();
      await expect(
        client
          .adminSetUserPassword({
            UserPoolId: userPoolId,
            Username: "jane",
            Password: "Password1",
            Permanent: true,
          })
          .promise(),
      ).rejects.toMatchObject({
        code: "InvalidPasswordException",
        message:
          "Password does not conform to policy: Password must have symbol characters",
      });
    });

    it("rejects a weak password in NEW_PASSWORD_REQUIRED, ChangePassword and ConfirmForgotPassword", async () => {
      const client = Cognito();
      const { userPoolId, clientId } = await setup(client);
      await client
        .adminCreateUser({
          UserPoolId: userPoolId,
          Username: "jane",
          MessageAction: "SUPPRESS",
          TemporaryPassword: "Temp-1234",
          UserAttributes: [{ Name: "email", Value: "jane@example.com" }],
        })
        .promise();

      const challenge = await signIn(client, clientId, "jane", "Temp-1234");
      expect(challenge.ChallengeName).toEqual("NEW_PASSWORD_REQUIRED");
      await expect(
        client
          .respondToAuthChallenge({
            ClientId: clientId,
            ChallengeName: "NEW_PASSWORD_REQUIRED",
            Session: challenge.Session,
            ChallengeResponses: { USERNAME: "jane", NEW_PASSWORD: "weak" },
          })
          .promise(),
      ).rejects.toMatchObject({ code: "InvalidPasswordException" });
      const tokens = await client
        .respondToAuthChallenge({
          ClientId: clientId,
          ChallengeName: "NEW_PASSWORD_REQUIRED",
          Session: challenge.Session,
          ChallengeResponses: { USERNAME: "jane", NEW_PASSWORD: STRONG },
        })
        .promise();

      await expect(
        client
          .changePassword({
            AccessToken: tokens.AuthenticationResult?.AccessToken as string,
            PreviousPassword: STRONG,
            ProposedPassword: "weak",
          })
          .promise(),
      ).rejects.toMatchObject({ code: "InvalidPasswordException" });

      await client
        .adminUpdateUserAttributes({
          UserPoolId: userPoolId,
          Username: "jane",
          UserAttributes: [{ Name: "email_verified", Value: "true" }],
        })
        .promise();
      await client
        .forgotPassword({ ClientId: clientId, Username: "jane" })
        .promise();
      const code = messageDelivery().collectedMessages.at(-1)?.message
        .__code as string;
      await expect(
        client
          .confirmForgotPassword({
            ClientId: clientId,
            Username: "jane",
            ConfirmationCode: code,
            Password: "weak",
          })
          .promise(),
      ).rejects.toMatchObject({ code: "InvalidPasswordException" });
    });
  }),
);

describe(
  "CognitoIdentityServiceProvider password policy turned off in config",
  withCognitoSdk(
    (Cognito) => {
      it("accepts any password", async () => {
        const client = Cognito();
        const { clientId } = await setup(client);

        const result = await client
          .signUp({ ClientId: clientId, Username: "jane", Password: "x" })
          .promise();

        expect(result.UserSub).toBeDefined();
      });
    },
    {
      config: { ...DefaultConfig, PasswordPolicyConfig: { Enforce: false } },
    },
  ),
);
