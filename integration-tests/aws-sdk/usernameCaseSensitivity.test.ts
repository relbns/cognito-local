import type { CognitoIdentityServiceProvider } from "aws-sdk";
import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "./setup";

const PASSWORD = "Password1!";

describe(
  "UsernameConfiguration.CaseSensitive",
  withCognitoSdk((Cognito) => {
    const setup = async (
      client: CognitoIdentityServiceProvider,
      options: Partial<CognitoIdentityServiceProvider.CreateUserPoolRequest>,
    ) => {
      const pool = await client
        .createUserPool({ PoolName: "test", ...options })
        .promise();
      const userPoolId = pool.UserPool?.Id as string;
      const appClient = await client
        .createUserPoolClient({
          UserPoolId: userPoolId,
          ClientName: "app",
          ExplicitAuthFlows: ["ALLOW_USER_PASSWORD_AUTH"],
        })
        .promise();
      return {
        userPoolId,
        clientId: appClient.UserPoolClient?.ClientId as string,
      };
    };

    const createUser = async (
      client: CognitoIdentityServiceProvider,
      userPoolId: string,
      username: string,
    ) => {
      await client
        .adminCreateUser({
          UserPoolId: userPoolId,
          Username: username,
          MessageAction: "SUPPRESS",
        })
        .promise();
      await client
        .adminSetUserPassword({
          UserPoolId: userPoolId,
          Username: username,
          Password: PASSWORD,
          Permanent: true,
        })
        .promise();
    };

    describe("false", () => {
      it("stores the username as given and finds it in any case", async () => {
        const client = Cognito();
        const { userPoolId, clientId } = await setup(client, {
          UsernameAttributes: [],
          UsernameConfiguration: { CaseSensitive: false },
        });
        await createUser(client, userPoolId, "Jane");

        const user = await client
          .adminGetUser({ UserPoolId: userPoolId, Username: "JANE" })
          .promise();
        expect(user.Username).toEqual("Jane");

        const auth = await client
          .initiateAuth({
            AuthFlow: "USER_PASSWORD_AUTH",
            ClientId: clientId,
            AuthParameters: { USERNAME: "jane", PASSWORD },
          })
          .promise();
        expect(auth.AuthenticationResult?.AccessToken).toBeDefined();

        await client
          .adminAddUserToGroup({
            UserPoolId: userPoolId,
            Username: "jAnE",
            GroupName: await client
              .createGroup({ UserPoolId: userPoolId, GroupName: "g" })
              .promise()
              .then(() => "g"),
          })
          .promise();
        const groups = await client
          .adminListGroupsForUser({ UserPoolId: userPoolId, Username: "JANE" })
          .promise();
        expect(groups.Groups?.map((g) => g.GroupName)).toEqual(["g"]);

        const listed = await client
          .listUsers({ UserPoolId: userPoolId, Filter: 'username = "jane"' })
          .promise();
        expect(listed.Users?.map((u) => u.Username)).toEqual(["Jane"]);
      });

      it("refuses a sign-up that differs only in case", async () => {
        const client = Cognito();
        const { userPoolId, clientId } = await setup(client, {
          UsernameAttributes: [],
          UsernameConfiguration: { CaseSensitive: false },
        });
        await createUser(client, userPoolId, "Jane");

        await expect(
          client
            .signUp({
              ClientId: clientId,
              Username: "JANE",
              Password: PASSWORD,
            })
            .promise(),
        ).rejects.toMatchObject({ code: "UsernameExistsException" });
        await expect(
          client
            .adminCreateUser({
              UserPoolId: userPoolId,
              Username: "jane",
              MessageAction: "SUPPRESS",
            })
            .promise(),
        ).rejects.toMatchObject({ code: "UsernameExistsException" });
      });

      it("signs in with the email in any case in an email-username pool", async () => {
        const client = Cognito();
        const { userPoolId, clientId } = await setup(client, {
          UsernameAttributes: ["email"],
          UsernameConfiguration: { CaseSensitive: false },
        });
        await createUser(client, userPoolId, "Jane@Example.test");

        const auth = await client
          .initiateAuth({
            AuthFlow: "USER_PASSWORD_AUTH",
            ClientId: clientId,
            AuthParameters: { USERNAME: "jane@example.test", PASSWORD },
          })
          .promise();
        expect(auth.AuthenticationResult?.AccessToken).toBeDefined();

        await expect(
          client
            .signUp({
              ClientId: clientId,
              Username: "JANE@EXAMPLE.TEST",
              Password: PASSWORD,
            })
            .promise(),
        ).rejects.toMatchObject({ code: "UsernameExistsException" });
      });
    });

    it("keeps usernames case-sensitive when UsernameConfiguration is omitted", async () => {
      const client = Cognito();
      const { userPoolId, clientId } = await setup(client, {
        UsernameAttributes: [],
      });
      await createUser(client, userPoolId, "Jane");
      await createUser(client, userPoolId, "jane");

      await expect(
        client
          .adminGetUser({ UserPoolId: userPoolId, Username: "JANE" })
          .promise(),
      ).rejects.toMatchObject({ code: "UserNotFoundException" });
      await expect(
        client
          .initiateAuth({
            AuthFlow: "USER_PASSWORD_AUTH",
            ClientId: clientId,
            AuthParameters: { USERNAME: "JANE", PASSWORD },
          })
          .promise(),
      ).rejects.toMatchObject({ code: "UserNotFoundException" });
    });
  }),
);
