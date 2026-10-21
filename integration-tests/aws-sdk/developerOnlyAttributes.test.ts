import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "./setup";

const PASSWORD = "Password1!";
const UNAUTHORIZED = {
  code: "NotAuthorizedException",
  message: "A client attempted to write unauthorized attribute",
};

describe(
  "Developer-only attributes",
  withCognitoSdk((Cognito) => {
    const setup = async () => {
      const client = Cognito();
      const pool = await client
        .createUserPool({
          PoolName: "test",
          UsernameAttributes: [],
          Schema: [
            {
              Name: "tier",
              AttributeDataType: "String",
              DeveloperOnlyAttribute: true,
              Mutable: true,
            },
          ],
        })
        .promise();
      const userPoolId = pool.UserPool?.Id as string;
      const appClient = await client
        .createUserPoolClient({
          UserPoolId: userPoolId,
          ClientName: "app",
          ExplicitAuthFlows: ["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
        })
        .promise();
      const clientId = appClient.UserPoolClient?.ClientId as string;
      await client
        .adminCreateUser({
          UserPoolId: userPoolId,
          Username: "jane",
          MessageAction: "SUPPRESS",
          UserAttributes: [{ Name: "dev:custom:tier", Value: "gold" }],
        })
        .promise();
      await client
        .adminSetUserPassword({
          UserPoolId: userPoolId,
          Username: "jane",
          Password: PASSWORD,
          Permanent: true,
        })
        .promise();
      const auth = await client
        .adminInitiateAuth({
          AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
          ClientId: clientId,
          UserPoolId: userPoolId,
          AuthParameters: { USERNAME: "jane", PASSWORD },
        })
        .promise();
      return {
        client,
        userPoolId,
        clientId,
        accessToken: auth.AuthenticationResult?.AccessToken as string,
      };
    };

    it("names the schema attribute dev:custom:<name>", async () => {
      const { client, userPoolId } = await setup();

      const pool = await client
        .describeUserPool({ UserPoolId: userPoolId })
        .promise();
      const names = pool.UserPool?.SchemaAttributes?.map((a) => a.Name);
      expect(names).toContain("dev:custom:tier");
      expect(names).not.toContain("custom:tier");
    });

    it("lets admin operations write it and users read it", async () => {
      const { client, userPoolId, accessToken } = await setup();

      await client
        .adminUpdateUserAttributes({
          UserPoolId: userPoolId,
          Username: "jane",
          UserAttributes: [{ Name: "dev:custom:tier", Value: "silver" }],
        })
        .promise();

      const user = await client.getUser({ AccessToken: accessToken }).promise();
      expect(user.UserAttributes).toContainEqual({
        Name: "dev:custom:tier",
        Value: "silver",
      });

      await client
        .adminDeleteUserAttributes({
          UserPoolId: userPoolId,
          Username: "jane",
          UserAttributeNames: ["dev:custom:tier"],
        })
        .promise();
      const admin = await client
        .adminGetUser({ UserPoolId: userPoolId, Username: "jane" })
        .promise();
      expect(admin.UserAttributes?.map((a) => a.Name)).not.toContain(
        "dev:custom:tier",
      );
    });

    it("refuses user-level writes", async () => {
      const { client, clientId, accessToken } = await setup();

      await expect(
        client
          .updateUserAttributes({
            AccessToken: accessToken,
            UserAttributes: [{ Name: "dev:custom:tier", Value: "platinum" }],
          })
          .promise(),
      ).rejects.toMatchObject(UNAUTHORIZED);

      await expect(
        client
          .deleteUserAttributes({
            AccessToken: accessToken,
            UserAttributeNames: ["dev:custom:tier"],
          })
          .promise(),
      ).rejects.toMatchObject(UNAUTHORIZED);

      await expect(
        client
          .signUp({
            ClientId: clientId,
            Username: "john",
            Password: PASSWORD,
            UserAttributes: [{ Name: "dev:custom:tier", Value: "gold" }],
          })
          .promise(),
      ).rejects.toMatchObject(UNAUTHORIZED);
    });
  }),
);
