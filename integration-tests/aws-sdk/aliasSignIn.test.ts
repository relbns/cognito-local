import type { CognitoIdentityServiceProvider } from "aws-sdk";
import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "./setup";

const PASSWORD = "Password1!";

const setUp = async (
  client: CognitoIdentityServiceProvider,
  attributes: CognitoIdentityServiceProvider.AttributeListType,
  pool: Partial<CognitoIdentityServiceProvider.CreateUserPoolRequest> = {},
) => {
  const created = await client
    .createUserPool({
      PoolName: "aliases",
      AliasAttributes: ["email", "phone_number", "preferred_username"],
      ...pool,
    })
    .promise();
  const userPoolId = created.UserPool?.Id as string;
  const appClient = await client
    .createUserPoolClient({
      UserPoolId: userPoolId,
      ClientName: "app",
      ExplicitAuthFlows: [
        "ALLOW_USER_PASSWORD_AUTH",
        "ALLOW_ADMIN_USER_PASSWORD_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
      ],
    })
    .promise();
  await client
    .adminCreateUser({
      UserPoolId: userPoolId,
      Username: "jane",
      TemporaryPassword: PASSWORD,
      MessageAction: "SUPPRESS",
      UserAttributes: attributes,
    })
    .promise();
  return {
    userPoolId,
    clientId: appClient.UserPoolClient?.ClientId as string,
  };
};

const confirmPassword = (
  client: CognitoIdentityServiceProvider,
  userPoolId: string,
) =>
  client
    .adminSetUserPassword({
      UserPoolId: userPoolId,
      Username: "jane",
      Password: PASSWORD,
      Permanent: true,
    })
    .promise();

describe(
  "Sign-in user resolution",
  withCognitoSdk((Cognito) => {
    it.each(["jane@example.test", "+15555550100", "JaneD"])(
      "signs in with the alias %s in a pool with AliasAttributes",
      async (alias) => {
        const client = Cognito();
        const { userPoolId, clientId } = await setUp(client, [
          { Name: "email", Value: "jane@example.test" },
          { Name: "email_verified", Value: "true" },
          { Name: "phone_number", Value: "+15555550100" },
          { Name: "phone_number_verified", Value: "true" },
          { Name: "preferred_username", Value: "JaneD" },
        ]);
        await confirmPassword(client, userPoolId);

        const auth = await client
          .initiateAuth({
            AuthFlow: "USER_PASSWORD_AUTH",
            ClientId: clientId,
            AuthParameters: { USERNAME: alias, PASSWORD },
          })
          .promise();

        expect(auth.AuthenticationResult?.AccessToken).toBeDefined();
        const user = await client
          .getUser({
            AccessToken: auth.AuthenticationResult?.AccessToken ?? "",
          })
          .promise();
        expect(user.Username).toEqual("jane");
      },
    );

    it("refuses an email alias that is not verified", async () => {
      const client = Cognito();
      const { userPoolId, clientId } = await setUp(client, [
        { Name: "email", Value: "jane@example.test" },
      ]);
      await confirmPassword(client, userPoolId);

      await expect(
        client
          .initiateAuth({
            AuthFlow: "USER_PASSWORD_AUTH",
            ClientId: clientId,
            AuthParameters: { USERNAME: "jane@example.test", PASSWORD },
          })
          .promise(),
      ).rejects.toMatchObject({ code: "NotAuthorizedException" });
    });

    it("matches an email alias in any case when the pool is not case sensitive", async () => {
      const client = Cognito();
      const { userPoolId } = await setUp(
        client,
        [
          { Name: "email", Value: "Jane@Example.test" },
          { Name: "email_verified", Value: "true" },
        ],
        { UsernameConfiguration: { CaseSensitive: false } },
      );

      const user = await client
        .adminGetUser({ UserPoolId: userPoolId, Username: "jane@example.TEST" })
        .promise();
      expect(user.Username).toEqual("jane");
    });

    it("answers ADMIN_USER_PASSWORD_AUTH with NEW_PASSWORD_REQUIRED for a temporary password", async () => {
      const client = Cognito();
      const { userPoolId, clientId } = await setUp(client, []);

      const auth = await client
        .adminInitiateAuth({
          AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
          ClientId: clientId,
          UserPoolId: userPoolId,
          AuthParameters: { USERNAME: "jane", PASSWORD },
        })
        .promise();
      expect(auth.ChallengeName).toEqual("NEW_PASSWORD_REQUIRED");
      expect(auth.AuthenticationResult).toBeUndefined();

      const done = await client
        .adminRespondToAuthChallenge({
          ClientId: clientId,
          UserPoolId: userPoolId,
          ChallengeName: "NEW_PASSWORD_REQUIRED",
          Session: auth.Session,
          ChallengeResponses: { USERNAME: "jane", NEW_PASSWORD: "Password2!" },
        })
        .promise();
      expect(done.AuthenticationResult?.AccessToken).toBeDefined();
      const user = await client
        .adminGetUser({ UserPoolId: userPoolId, Username: "jane" })
        .promise();
      expect(user.UserStatus).toEqual("CONFIRMED");
    });
  }),
);
