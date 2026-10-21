import type { CognitoIdentityServiceProvider } from "aws-sdk";
import { beforeEach, describe, expect, it } from "vitest";
import { fakeLambdaClient } from "../../src/__tests__/fakeLambdaClient";
import { type Lambda, LambdaService } from "../../src/services";
import { withCognitoSdk } from "./setup";

type TriggerEvent = {
  triggerSource: string;
  userPoolId: string;
  userName: string;
  request: Record<string, any>;
  response: Record<string, any>;
};

const PASSWORD = "Password1!";

let handlers: Record<string, (event: TriggerEvent) => unknown> = {};
let invocations: { name: string; event: TriggerEvent }[] = [];

const lambdaService = new LambdaService(
  Object.fromEntries(
    [
      "CustomEmailSender",
      "PostAuthentication",
      "PreSignUp",
      "UserMigration",
    ].map((name) => [name, name]),
  ),
  fakeLambdaClient(async (name, event: TriggerEvent) => {
    invocations.push({ name, event: structuredClone(event) });
    await handlers[name]?.(event);
    return event;
  }),
);

const lambda = (): Lambda => ({
  enabled: (name) => name in handlers,
  invoke: lambdaService.invoke.bind(lambdaService) as Lambda["invoke"],
});

const eventsFor = (name: string) =>
  invocations.filter((x) => x.name === name).map((x) => x.event);

const createPool = async (
  client: CognitoIdentityServiceProvider,
  options: Partial<CognitoIdentityServiceProvider.CreateUserPoolRequest> = {},
) => {
  const pool = await client
    .createUserPool({ PoolName: "test", UsernameAttributes: [], ...options })
    .promise();
  const userPoolId = pool.UserPool?.Id as string;
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
  return {
    userPoolId,
    clientId: appClient.UserPoolClient?.ClientId as string,
  };
};

describe(
  "Trigger events",
  withCognitoSdk(
    (Cognito) => {
      beforeEach(() => {
        handlers = {};
        invocations = [];
      });

      describe("PreSignUp", () => {
        it("receives SignUp ValidationData as validationData", async () => {
          const client = Cognito();
          const { clientId } = await createPool(client);
          handlers.PreSignUp = () => {};

          await client
            .signUp({
              ClientId: clientId,
              Username: "jane",
              Password: PASSWORD,
              ValidationData: [
                { Name: "invite", Value: "abc123" },
                { Name: "source", Value: "web" },
              ],
            })
            .promise();

          const [event] = eventsFor("PreSignUp");
          expect(event.triggerSource).toEqual("PreSignUp_SignUp");
          expect(event.request.validationData).toEqual({
            invite: "abc123",
            source: "web",
          });
        });
      });

      describe("PreSignUp on AdminCreateUser", () => {
        it("runs with PreSignUp_AdminCreateUser and leaves the user FORCE_CHANGE_PASSWORD", async () => {
          const client = Cognito();
          const { userPoolId } = await createPool(client);
          handlers.PreSignUp = (event) => {
            event.response.autoConfirmUser = true;
            event.response.autoVerifyEmail = true;
          };

          const created = await client
            .adminCreateUser({
              UserPoolId: userPoolId,
              Username: "jane",
              MessageAction: "SUPPRESS",
              UserAttributes: [{ Name: "email", Value: "jane@example.test" }],
              ValidationData: [{ Name: "invite", Value: "abc123" }],
              ClientMetadata: { source: "admin" },
            })
            .promise();

          const [event] = eventsFor("PreSignUp");
          expect(event.triggerSource).toEqual("PreSignUp_AdminCreateUser");
          expect(event.userName).toEqual("jane");
          expect(event.request.validationData).toEqual({ invite: "abc123" });
          expect(event.request.clientMetadata).toEqual({ source: "admin" });
          expect(event.request.userAttributes.email).toEqual(
            "jane@example.test",
          );
          expect(created.User?.UserStatus).toEqual("FORCE_CHANGE_PASSWORD");
        });

        it("does not create the user when the trigger throws", async () => {
          const client = Cognito();
          const { userPoolId } = await createPool(client);
          handlers.PreSignUp = () => {
            throw new Error("denied");
          };

          await expect(
            client
              .adminCreateUser({
                UserPoolId: userPoolId,
                Username: "jane",
                MessageAction: "SUPPRESS",
              })
              .promise(),
          ).rejects.toMatchObject({
            code: "UserLambdaValidationException",
            message: "PreSignUp failed with error denied.",
          });
          await expect(
            client
              .adminGetUser({ UserPoolId: userPoolId, Username: "jane" })
              .promise(),
          ).rejects.toMatchObject({ code: "UserNotFoundException" });
        });
      });

      describe("UserMigration", () => {
        it("creates the user under the sign-in username with a sub", async () => {
          const client = Cognito();
          const { userPoolId, clientId } = await createPool(client);
          handlers.UserMigration = (event) => {
            event.response.userAttributes = {
              email: "jane@example.test",
              email_verified: "true",
            };
            event.response.finalUserStatus = "CONFIRMED";
            event.response.messageAction = "SUPPRESS";
          };

          const auth = await client
            .initiateAuth({
              AuthFlow: "USER_PASSWORD_AUTH",
              ClientId: clientId,
              AuthParameters: { USERNAME: "jane", PASSWORD: PASSWORD },
              ClientMetadata: { source: "web" },
            })
            .promise();
          expect(auth.AuthenticationResult?.AccessToken).toBeDefined();

          const [event] = eventsFor("UserMigration");
          expect(event.userName).toEqual("jane");
          expect(event.request.validationData).toEqual({ source: "web" });

          const user = await client
            .adminGetUser({ UserPoolId: userPoolId, Username: "jane" })
            .promise();
          expect(user.Username).toEqual("jane");
          expect(user.UserStatus).toEqual("CONFIRMED");
          expect(
            user.UserAttributes?.find((a) => a.Name === "sub")?.Value,
          ).toMatch(/^[0-9a-f-]{36}$/);
        });

        it("leaves the user RESET_REQUIRED when finalUserStatus is not returned", async () => {
          const client = Cognito();
          const { userPoolId, clientId } = await createPool(client);
          handlers.UserMigration = (event) => {
            event.response.userAttributes = { email: "jane@example.test" };
          };

          await expect(
            client
              .adminInitiateAuth({
                AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
                ClientId: clientId,
                UserPoolId: userPoolId,
                AuthParameters: { USERNAME: "jane", PASSWORD: PASSWORD },
                ClientMetadata: { source: "admin" },
              })
              .promise(),
          ).rejects.toMatchObject({ code: "PasswordResetRequiredException" });

          expect(eventsFor("UserMigration")[0].request.validationData).toEqual({
            source: "admin",
          });
          const user = await client
            .adminGetUser({ UserPoolId: userPoolId, Username: "jane" })
            .promise();
          expect(user.UserStatus).toEqual("RESET_REQUIRED");
        });

        it("identifies the user by sub in a pool that signs in with email", async () => {
          const client = Cognito();
          const { userPoolId, clientId } = await createPool(client, {
            UsernameAttributes: ["email"],
          });
          handlers.UserMigration = (event) => {
            event.response.userAttributes = { email_verified: "true" };
            event.response.finalUserStatus = "CONFIRMED";
          };

          await client
            .initiateAuth({
              AuthFlow: "USER_PASSWORD_AUTH",
              ClientId: clientId,
              AuthParameters: {
                USERNAME: "jane@example.test",
                PASSWORD: PASSWORD,
              },
            })
            .promise();

          const user = await client
            .adminGetUser({
              UserPoolId: userPoolId,
              Username: "jane@example.test",
            })
            .promise();
          const sub = user.UserAttributes?.find((a) => a.Name === "sub")?.Value;
          expect(user.Username).toEqual(sub);
          expect(
            user.UserAttributes?.find((a) => a.Name === "email")?.Value,
          ).toEqual("jane@example.test");
        });
      });
    },
    { lambda },
  ),
);
