import {
  CognitoIdentityProviderClient,
  CreateUserPoolClientCommand,
  CreateUserPoolCommand,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import type { CognitoIdentityServiceProvider } from "aws-sdk";
import { beforeEach, describe, expect, it } from "vitest";
import { fakeLambdaClient } from "../../src/__tests__/fakeLambdaClient";
import { type Lambda, LambdaService } from "../../src/services";
import type { Context } from "../../src/services/context";
import { CryptoService } from "../../src/services/crypto";
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
      "CustomSMSSender",
      "PostAuthentication",
      "PreAuthentication",
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

class FakeCrypto extends CryptoService {
  async encrypt(_ctx: Context, plaintext: string): Promise<string> {
    return `encrypted:${plaintext}`;
  }
}

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
    (Cognito, { codeLog, messageDelivery, serverUrl }) => {
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

      describe("PreAuthentication", () => {
        const createUser = (
          client: CognitoIdentityServiceProvider,
          userPoolId: string,
        ) =>
          client
            .adminCreateUser({
              UserPoolId: userPoolId,
              Username: "jane",
              TemporaryPassword: PASSWORD,
              MessageAction: "SUPPRESS",
              UserAttributes: [{ Name: "email", Value: "jane@example.test" }],
            })
            .promise()
            .then(() =>
              client
                .adminSetUserPassword({
                  UserPoolId: userPoolId,
                  Username: "jane",
                  Password: PASSWORD,
                  Permanent: true,
                })
                .promise(),
            );

        it("runs before a password sign-in with ClientMetadata as validationData", async () => {
          const client = Cognito();
          const { userPoolId, clientId } = await createPool(client);
          await createUser(client, userPoolId);
          handlers.PreAuthentication = () => {};
          handlers.PostAuthentication = () => {};

          await client
            .initiateAuth({
              AuthFlow: "USER_PASSWORD_AUTH",
              ClientId: clientId,
              AuthParameters: { USERNAME: "jane", PASSWORD: PASSWORD },
              ClientMetadata: { source: "web" },
            })
            .promise();

          expect(invocations.map((x) => x.name)).toEqual([
            "PreAuthentication",
            "PostAuthentication",
          ]);
          const [event] = eventsFor("PreAuthentication");
          expect(event.triggerSource).toEqual(
            "PreAuthentication_Authentication",
          );
          expect(event.userName).toEqual("jane");
          expect(event.request.userAttributes.email).toEqual(
            "jane@example.test",
          );
          expect(event.request.validationData).toEqual({ source: "web" });
          expect(event.request).not.toHaveProperty("userNotFound");
        });

        it("rejects the sign-in with UserLambdaValidationException when it throws", async () => {
          const client = Cognito();
          const { userPoolId, clientId } = await createPool(client);
          await createUser(client, userPoolId);
          handlers.PreAuthentication = () => {
            throw new Error("blocked");
          };

          await expect(
            client
              .adminInitiateAuth({
                AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
                ClientId: clientId,
                UserPoolId: userPoolId,
                AuthParameters: { USERNAME: "jane", PASSWORD: PASSWORD },
              })
              .promise(),
          ).rejects.toMatchObject({
            code: "UserLambdaValidationException",
            message: "PreAuthentication failed with error blocked.",
          });
        });

        it("runs for an unknown user with userNotFound when the client prevents user existence errors", async () => {
          const client = Cognito();
          const { userPoolId } = await createPool(client);
          const appClient = await client
            .createUserPoolClient({
              UserPoolId: userPoolId,
              ClientName: "strict",
              ExplicitAuthFlows: ["ALLOW_USER_PASSWORD_AUTH"],
              PreventUserExistenceErrors: "ENABLED",
            })
            .promise();
          handlers.PreAuthentication = () => {};

          await expect(
            client
              .initiateAuth({
                AuthFlow: "USER_PASSWORD_AUTH",
                ClientId: appClient.UserPoolClient?.ClientId as string,
                AuthParameters: { USERNAME: "nobody", PASSWORD: PASSWORD },
              })
              .promise(),
          ).rejects.toMatchObject({ code: "NotAuthorizedException" });

          const [event] = eventsFor("PreAuthentication");
          expect(event.userName).toEqual("nobody");
          expect(event.request.userNotFound).toBe(true);
          expect(event.request.userAttributes).toEqual({});
        });
      });

      describe("CustomSMSSender", () => {
        const PHONE = "+15555550100";

        const expectSentBySmsSender = (source: string) => {
          const events = eventsFor("CustomSMSSender");
          expect(events.map((e) => e.triggerSource)).toEqual([source]);
          const [event] = events;
          expect(event.request.type).toEqual("customSMSSenderRequestV1");
          expect(event.request.userAttributes.phone_number).toEqual(PHONE);
          const code = event.request.code.replace(/^encrypted:/, "");
          expect(codeLog().list()[0]).toMatchObject({
            code,
            deliveryMedium: "SMS",
            destination: PHONE,
          });
          expect(messageDelivery().collectedMessages).toEqual([]);
          return code;
        };

        it("sends the sign-up code with CustomSMSSender_SignUp", async () => {
          const client = Cognito();
          const { userPoolId, clientId } = await createPool(client, {
            AutoVerifiedAttributes: ["phone_number"],
          });
          handlers.CustomSMSSender = () => {};
          handlers.CustomEmailSender = () => {};

          await client
            .signUp({
              ClientId: clientId,
              Username: "jane",
              Password: PASSWORD,
              UserAttributes: [{ Name: "phone_number", Value: PHONE }],
            })
            .promise();

          const code = expectSentBySmsSender("CustomSMSSender_SignUp");
          expect(eventsFor("CustomEmailSender")).toEqual([]);
          await client
            .confirmSignUp({
              ClientId: clientId,
              Username: "jane",
              ConfirmationCode: code,
            })
            .promise();
          const user = await client
            .adminGetUser({ UserPoolId: userPoolId, Username: "jane" })
            .promise();
          expect(user.UserStatus).toEqual("CONFIRMED");
        });

        it("sends the temporary password with CustomSMSSender_AdminCreateUser", async () => {
          const client = Cognito();
          const { userPoolId } = await createPool(client);
          handlers.CustomSMSSender = () => {};

          await client
            .adminCreateUser({
              UserPoolId: userPoolId,
              Username: "jane",
              DesiredDeliveryMediums: ["SMS"],
              UserAttributes: [{ Name: "phone_number", Value: PHONE }],
            })
            .promise();

          expectSentBySmsSender("CustomSMSSender_AdminCreateUser");
        });

        it("sends the MFA code with CustomSMSSender_Authentication", async () => {
          const client = Cognito();
          const { userPoolId, clientId } = await createPool(client, {
            MfaConfiguration: "OPTIONAL",
          });
          await client
            .adminCreateUser({
              UserPoolId: userPoolId,
              Username: "jane",
              MessageAction: "SUPPRESS",
              UserAttributes: [
                { Name: "phone_number", Value: PHONE },
                { Name: "phone_number_verified", Value: "true" },
              ],
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
          await client
            .adminSetUserSettings({
              UserPoolId: userPoolId,
              Username: "jane",
              MFAOptions: [
                { DeliveryMedium: "SMS", AttributeName: "phone_number" },
              ],
            })
            .promise();
          handlers.CustomSMSSender = () => {};

          const auth = await client
            .initiateAuth({
              AuthFlow: "USER_PASSWORD_AUTH",
              ClientId: clientId,
              AuthParameters: { USERNAME: "jane", PASSWORD: PASSWORD },
            })
            .promise();

          expect(auth.ChallengeName).toEqual("SMS_MFA");
          expectSentBySmsSender("CustomSMSSender_Authentication");
        });

        it.each(["initiateAuth", "adminInitiateAuth"] as const)(
          "%s sends the MFA code of a user whose SMS MFA is set by AdminSetUserMFAPreference",
          async (operation) => {
            const client = Cognito();
            const { userPoolId, clientId } = await createPool(client, {
              MfaConfiguration: "OPTIONAL",
            });
            await client
              .adminCreateUser({
                UserPoolId: userPoolId,
                Username: "jane",
                MessageAction: "SUPPRESS",
                UserAttributes: [
                  { Name: "phone_number", Value: PHONE },
                  { Name: "phone_number_verified", Value: "true" },
                ],
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
            await client
              .adminSetUserMFAPreference({
                UserPoolId: userPoolId,
                Username: "jane",
                SMSMfaSettings: { Enabled: true, PreferredMfa: true },
              })
              .promise();
            handlers.CustomSMSSender = () => {};

            const auth =
              operation === "initiateAuth"
                ? await client
                    .initiateAuth({
                      AuthFlow: "USER_PASSWORD_AUTH",
                      ClientId: clientId,
                      AuthParameters: { USERNAME: "jane", PASSWORD: PASSWORD },
                    })
                    .promise()
                : await client
                    .adminInitiateAuth({
                      AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
                      ClientId: clientId,
                      UserPoolId: userPoolId,
                      AuthParameters: { USERNAME: "jane", PASSWORD: PASSWORD },
                    })
                    .promise();

            expect(auth.ChallengeName).toEqual("SMS_MFA");
            const code = expectSentBySmsSender(
              "CustomSMSSender_Authentication",
            );
            const challengeResponses = { USERNAME: "jane", SMS_MFA_CODE: code };
            const tokens =
              operation === "initiateAuth"
                ? await client
                    .respondToAuthChallenge({
                      ClientId: clientId,
                      ChallengeName: "SMS_MFA",
                      Session: auth.Session,
                      ChallengeResponses: challengeResponses,
                    })
                    .promise()
                : await client
                    .adminRespondToAuthChallenge({
                      ClientId: clientId,
                      UserPoolId: userPoolId,
                      ChallengeName: "SMS_MFA",
                      Session: auth.Session,
                      ChallengeResponses: challengeResponses,
                    })
                    .promise();
            expect(tokens.AuthenticationResult?.AccessToken).toBeDefined();
          },
        );
      });

      describe("USER_AUTH", () => {
        it("runs PreAuthentication once and sends the EMAIL_OTP code with CustomEmailSender_Authentication", async () => {
          const v3 = new CognitoIdentityProviderClient({
            endpoint: serverUrl(),
            region: "local",
            credentials: { accessKeyId: "local", secretAccessKey: "local" },
            maxAttempts: 1,
          });
          const pool = await v3.send(
            new CreateUserPoolCommand({
              PoolName: "user-auth",
              Policies: {
                SignInPolicy: {
                  AllowedFirstAuthFactors: ["PASSWORD", "EMAIL_OTP"],
                },
              },
            }),
          );
          const userPoolId = pool.UserPool?.Id as string;
          const appClient = await v3.send(
            new CreateUserPoolClientCommand({
              UserPoolId: userPoolId,
              ClientName: "app",
              ExplicitAuthFlows: ["ALLOW_USER_AUTH"],
            }),
          );
          const clientId = appClient.UserPoolClient?.ClientId as string;
          await Cognito()
            .adminCreateUser({
              UserPoolId: userPoolId,
              Username: "jane",
              MessageAction: "SUPPRESS",
              UserAttributes: [{ Name: "email", Value: "jane@example.test" }],
            })
            .promise();
          await Cognito()
            .adminSetUserPassword({
              UserPoolId: userPoolId,
              Username: "jane",
              Password: PASSWORD,
              Permanent: true,
            })
            .promise();
          handlers.PreAuthentication = () => {};
          handlers.CustomEmailSender = () => {};

          const select = await v3.send(
            new InitiateAuthCommand({
              AuthFlow: "USER_AUTH",
              ClientId: clientId,
              AuthParameters: { USERNAME: "jane" },
              ClientMetadata: { source: "web" },
            }),
          );
          expect(select.ChallengeName).toEqual("SELECT_CHALLENGE");
          const otp = await v3.send(
            new RespondToAuthChallengeCommand({
              ClientId: clientId,
              ChallengeName: "SELECT_CHALLENGE",
              Session: select.Session,
              ChallengeResponses: { USERNAME: "jane", ANSWER: "EMAIL_OTP" },
            }),
          );
          expect(otp.ChallengeName).toEqual("EMAIL_OTP");

          const [sent] = eventsFor("CustomEmailSender");
          expect(sent.triggerSource).toEqual(
            "CustomEmailSender_Authentication",
          );
          expect(messageDelivery().collectedMessages).toEqual([]);
          const tokens = await v3.send(
            new RespondToAuthChallengeCommand({
              ClientId: clientId,
              ChallengeName: "EMAIL_OTP",
              Session: otp.Session,
              ChallengeResponses: {
                USERNAME: "jane",
                EMAIL_OTP_CODE: sent.request.code.replace(/^encrypted:/, ""),
              },
            }),
          );
          expect(tokens.AuthenticationResult?.AccessToken).toBeDefined();

          const preAuth = eventsFor("PreAuthentication");
          expect(preAuth).toHaveLength(1);
          expect(preAuth[0].request.validationData).toEqual({ source: "web" });
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
    { lambda, crypto: () => new FakeCrypto() },
  ),
);
