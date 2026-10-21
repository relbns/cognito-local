import {
  AdminAddUserToGroupCommand,
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  CognitoIdentityProviderClient,
  CreateGroupCommand,
  CreateUserPoolClientCommand,
  CreateUserPoolCommand,
  InitiateAuthCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import jwt from "jsonwebtoken";
import { describe, expect, it } from "vitest";
import { fakeLambdaClient } from "../../src/__tests__/fakeLambdaClient";
import { LambdaService } from "../../src/services";
import { withCognitoSdk } from "../aws-sdk/setup";

const PASSWORD = "Passw0rd!";
const credentials = { accessKeyId: "local", secretAccessKey: "local" };
const events: any[] = [];

const preTokenGenerationLambda = () =>
  new LambdaService(
    { PreTokenGeneration: "pre-token" },
    fakeLambdaClient((_name, event) => {
      events.push(structuredClone(event));
      if (event.version === "1") {
        event.response.claimsOverrideDetails = {
          claimsToAddOrOverride: { tenant: "t1" },
        };
      } else {
        event.response.claimsAndScopeOverrideDetails = {
          idTokenGeneration: { claimsToAddOrOverride: { tenant: "t1" } },
          accessTokenGeneration: {
            claimsToAddOrOverride: { tenant: { id: "t1" } },
            scopesToAdd: ["example.test/read"],
          },
        };
      }
      return event;
    }),
  );

describe(
  "pre token generation event versions",
  withCognitoSdk(
    (_, { serverUrl }) => {
      const signIn = async (lambdaVersion: string | undefined) => {
        events.length = 0;
        const cognito = new CognitoIdentityProviderClient({
          region: "us-east-1",
          endpoint: serverUrl(),
          credentials,
        });
        const pool = await cognito.send(
          new CreateUserPoolCommand({
            PoolName: "ptg",
            LambdaConfig: lambdaVersion
              ? {
                  PreTokenGenerationConfig: {
                    LambdaArn:
                      "arn:aws:lambda:us-east-1:000000000000:function:pre-token",
                    LambdaVersion: lambdaVersion as "V2_0",
                  },
                }
              : undefined,
          }),
        );
        const UserPoolId = pool.UserPool!.Id!;
        const app = await cognito.send(
          new CreateUserPoolClientCommand({
            UserPoolId,
            ClientName: "web",
            ExplicitAuthFlows: ["ALLOW_USER_PASSWORD_AUTH"],
          }),
        );
        await cognito.send(
          new CreateGroupCommand({
            UserPoolId,
            GroupName: "admins",
            RoleArn: "arn:aws:iam::000000000000:role/admins",
            Precedence: 1,
          }),
        );
        await cognito.send(
          new AdminCreateUserCommand({
            UserPoolId,
            Username: "jane",
            MessageAction: "SUPPRESS",
          }),
        );
        await cognito.send(
          new AdminSetUserPasswordCommand({
            UserPoolId,
            Username: "jane",
            Password: PASSWORD,
            Permanent: true,
          }),
        );
        await cognito.send(
          new AdminAddUserToGroupCommand({
            UserPoolId,
            Username: "jane",
            GroupName: "admins",
          }),
        );
        const auth = await cognito.send(
          new InitiateAuthCommand({
            ClientId: app.UserPoolClient!.ClientId!,
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: { USERNAME: "jane", PASSWORD },
          }),
        );
        return {
          id: jwt.decode(auth.AuthenticationResult!.IdToken!) as Record<
            string,
            unknown
          >,
          access: jwt.decode(auth.AuthenticationResult!.AccessToken!) as Record<
            string,
            unknown
          >,
        };
      };

      const groupConfiguration = {
        groupsToOverride: ["admins"],
        iamRolesToOverride: ["arn:aws:iam::000000000000:role/admins"],
        preferredRole: "arn:aws:iam::000000000000:role/admins",
      };

      it("sends a version 1 event and customizes the ID token only", async () => {
        const { id, access } = await signIn(undefined);

        expect(events).toHaveLength(1);
        expect(events[0]).toMatchObject({
          version: "1",
          triggerSource: "TokenGeneration_Authentication",
          request: { groupConfiguration },
        });
        expect(events[0].request).not.toHaveProperty("scopes");
        expect(id).toMatchObject({
          tenant: "t1",
          "cognito:roles": ["arn:aws:iam::000000000000:role/admins"],
        });
        expect(access).not.toHaveProperty("tenant");
      });

      it("sends a version 2 event and customizes both tokens", async () => {
        const { id, access } = await signIn("V2_0");

        expect(events[0]).toMatchObject({
          version: "2",
          request: {
            groupConfiguration,
            scopes: ["aws.cognito.signin.user.admin"],
          },
          response: { claimsAndScopeOverrideDetails: null },
        });
        expect(id.tenant).toBe("t1");
        expect(access).toMatchObject({
          tenant: { id: "t1" },
          scope: "aws.cognito.signin.user.admin example.test/read",
          "cognito:groups": ["admins"],
        });
      });

      it("sends a version 3 event for user sign-in", async () => {
        await signIn("V3_0");
        expect(events[0].version).toBe("3");
      });
    },
    { lambda: preTokenGenerationLambda },
  ),
);
