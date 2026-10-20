import { describe, expect, it } from "vitest";
import { ClockFake } from "../../src/__tests__/clockFake";
import { withCognitoSdk } from "./setup";

const currentDate = new Date();
const roundedDate = new Date(currentDate.getTime());
roundedDate.setMilliseconds(0);

const clock = new ClockFake(currentDate);

describe(
  "CognitoIdentityServiceProvider.createGroup",
  withCognitoSdk(
    (Cognito) => {
      it("creates a group with only the required parameters", async () => {
        const client = Cognito();

        const pool = await client
          .createUserPool({
            PoolName: "test",
          })
          .promise();
        const userPoolId = pool.UserPool?.Id!;

        const createGroupResult = await client
          .createGroup({
            GroupName: "abc",
            UserPoolId: userPoolId,
          })
          .promise();

        expect(createGroupResult).toEqual({
          Group: {
            CreationDate: roundedDate,
            GroupName: "abc",
            LastModifiedDate: roundedDate,
            UserPoolId: userPoolId,
          },
        });
      });

      it("creates a group with all parameters", async () => {
        const client = Cognito();

        const pool = await client
          .createUserPool({
            PoolName: "test",
          })
          .promise();
        const userPoolId = pool.UserPool?.Id!;

        const createGroupResult = await client
          .createGroup({
            Description: "Description",
            GroupName: "abc",
            Precedence: 1,
            RoleArn: "arn",
            UserPoolId: userPoolId,
          })
          .promise();

        expect(createGroupResult).toEqual({
          Group: {
            CreationDate: roundedDate,
            Description: "Description",
            GroupName: "abc",
            LastModifiedDate: roundedDate,
            Precedence: 1,
            RoleArn: "arn",
            UserPoolId: userPoolId,
          },
        });
      });

      it("throws GroupExistsException for a duplicate name and keeps the members", async () => {
        const client = Cognito();
        const pool = await client
          .createUserPool({ PoolName: "test" })
          .promise();
        const userPoolId = pool.UserPool?.Id!;
        await client
          .createGroup({ GroupName: "abc", UserPoolId: userPoolId })
          .promise();
        await client
          .adminCreateUser({
            UserPoolId: userPoolId,
            Username: "jane@example.com",
            MessageAction: "SUPPRESS",
          })
          .promise();
        await client
          .adminAddUserToGroup({
            GroupName: "abc",
            UserPoolId: userPoolId,
            Username: "jane@example.com",
          })
          .promise();

        await expect(
          client
            .createGroup({ GroupName: "abc", UserPoolId: userPoolId })
            .promise(),
        ).rejects.toMatchObject({
          code: "GroupExistsException",
          message: "A group with the name abc already exists.",
        });

        const members = await client
          .listUsersInGroup({ GroupName: "abc", UserPoolId: userPoolId })
          .promise();
        expect(members.Users).toHaveLength(1);
      });
    },
    {
      clock,
    },
  ),
);
