import { describe, expect, it } from "vitest";
import { ClockFake } from "../../src/__tests__/clockFake";
import { withCognitoSdk } from "./setup";

const originalDate = new Date();
const roundedDate = new Date(originalDate.getTime());
roundedDate.setMilliseconds(0);

const clock = new ClockFake(originalDate);

describe(
  "CognitoIdentityServiceProvider.adminListGroupsForUser",
  withCognitoSdk(
    (Cognito) => {
      it("lists groups for a user", async () => {
        const client = Cognito();

        const pool = await client
          .createUserPool({
            PoolName: "test",
          })
          .promise();
        const userPoolId = pool.UserPool?.Id!;

        const createGroupResponse = await client
          .createGroup({
            GroupName: "group-1",
            UserPoolId: userPoolId,
          })
          .promise();

        await client
          .adminCreateUser({
            DesiredDeliveryMediums: ["EMAIL"],
            TemporaryPassword: "def-Aa1!",
            UserAttributes: [{ Name: "email", Value: "example+1@example.com" }],
            Username: "user-1",
            UserPoolId: userPoolId,
          })
          .promise();

        await client
          .adminAddUserToGroup({
            Username: "user-1",
            GroupName: "group-1",
            UserPoolId: userPoolId,
          })
          .promise();

        const result = await client
          .adminListGroupsForUser({
            UserPoolId: userPoolId,
            Username: "user-1",
          })
          .promise();

        expect(result.Groups).toEqual([createGroupResponse.Group]);
      });

      it("lists groups for a user addressed by email in an email-username pool", async () => {
        const client = Cognito();

        const pool = await client
          .createUserPool({
            PoolName: "test",
            UsernameAttributes: ["email"],
          })
          .promise();
        const userPoolId = pool.UserPool?.Id!;

        const createGroupResponse = await client
          .createGroup({ GroupName: "group-1", UserPoolId: userPoolId })
          .promise();

        await client
          .adminCreateUser({
            MessageAction: "SUPPRESS",
            TemporaryPassword: "def-Aa1!",
            Username: "jane@example.test",
            UserPoolId: userPoolId,
          })
          .promise();

        await client
          .adminAddUserToGroup({
            Username: "jane@example.test",
            GroupName: "group-1",
            UserPoolId: userPoolId,
          })
          .promise();

        const byEmail = await client
          .adminListGroupsForUser({
            UserPoolId: userPoolId,
            Username: "jane@example.test",
          })
          .promise();
        expect(byEmail.Groups).toEqual([createGroupResponse.Group]);

        const members = await client
          .listUsersInGroup({ UserPoolId: userPoolId, GroupName: "group-1" })
          .promise();
        expect(members.Users).toHaveLength(1);

        await client
          .adminRemoveUserFromGroup({
            Username: "jane@example.test",
            GroupName: "group-1",
            UserPoolId: userPoolId,
          })
          .promise();

        const afterRemove = await client
          .adminListGroupsForUser({
            UserPoolId: userPoolId,
            Username: "jane@example.test",
          })
          .promise();
        expect(afterRemove.Groups).toHaveLength(0);
      });

      it("lists groups for an unassigned user", async () => {
        const client = Cognito();

        const pool = await client
          .createUserPool({
            PoolName: "test",
          })
          .promise();
        const userPoolId = pool.UserPool?.Id!;

        await client
          .createGroup({
            GroupName: "group-2",
            UserPoolId: userPoolId,
          })
          .promise();

        await client
          .adminCreateUser({
            DesiredDeliveryMediums: ["EMAIL"],
            TemporaryPassword: "def-Aa1!",
            UserAttributes: [{ Name: "email", Value: "example+1@example.com" }],
            Username: "user-1",
            UserPoolId: userPoolId,
          })
          .promise();

        const result = await client
          .adminListGroupsForUser({
            UserPoolId: userPoolId,
            Username: "user-1",
          })
          .promise();

        expect(result.Groups).toHaveLength(0);
      });
    },
    {
      clock,
    },
  ),
);
