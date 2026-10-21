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
    },
    { lambda },
  ),
);
