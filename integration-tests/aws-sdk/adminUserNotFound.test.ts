import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "./setup";

describe(
  "CognitoIdentityServiceProvider admin operations on a missing user",
  withCognitoSdk((Cognito) => {
    const calls: Record<
      string,
      (userPoolId: string) => { promise(): Promise<unknown> }
    > = {
      adminConfirmSignUp: (UserPoolId) =>
        Cognito().adminConfirmSignUp({ UserPoolId, Username: "missing" }),
      adminDeleteUser: (UserPoolId) =>
        Cognito().adminDeleteUser({ UserPoolId, Username: "missing" }),
      adminDeleteUserAttributes: (UserPoolId) =>
        Cognito().adminDeleteUserAttributes({
          UserPoolId,
          Username: "missing",
          UserAttributeNames: ["name"],
        }),
      adminDisableUser: (UserPoolId) =>
        Cognito().adminDisableUser({ UserPoolId, Username: "missing" }),
      adminEnableUser: (UserPoolId) =>
        Cognito().adminEnableUser({ UserPoolId, Username: "missing" }),
      adminGetUser: (UserPoolId) =>
        Cognito().adminGetUser({ UserPoolId, Username: "missing" }),
      adminListGroupsForUser: (UserPoolId) =>
        Cognito().adminListGroupsForUser({ UserPoolId, Username: "missing" }),
      adminResetUserPassword: (UserPoolId) =>
        Cognito().adminResetUserPassword({ UserPoolId, Username: "missing" }),
      adminSetUserPassword: (UserPoolId) =>
        Cognito().adminSetUserPassword({
          UserPoolId,
          Username: "missing",
          Password: "Password1!",
        }),
      adminUpdateUserAttributes: (UserPoolId) =>
        Cognito().adminUpdateUserAttributes({
          UserPoolId,
          Username: "missing",
          UserAttributes: [{ Name: "name", Value: "Jane" }],
        }),
      adminUserGlobalSignOut: (UserPoolId) =>
        Cognito().adminUserGlobalSignOut({ UserPoolId, Username: "missing" }),
    };

    for (const [operation, call] of Object.entries(calls)) {
      it(`${operation} returns UserNotFoundException`, async () => {
        const pool = await Cognito()
          .createUserPool({ PoolName: "test", UsernameAttributes: [] })
          .promise();

        await expect(
          call(pool.UserPool?.Id as string).promise(),
        ).rejects.toMatchObject({
          code: "UserNotFoundException",
          message: "User does not exist.",
        });
      });
    }
  }),
);
