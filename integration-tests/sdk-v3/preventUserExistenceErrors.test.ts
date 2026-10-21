import {
  AdminCreateUserCommand,
  AdminInitiateAuthCommand,
  AdminResetUserPasswordCommand,
  AdminSetUserPasswordCommand,
  CognitoIdentityProviderClient,
  ConfirmForgotPasswordCommand,
  ConfirmSignUpCommand,
  CreateUserPoolClientCommand,
  CreateUserPoolCommand,
  ForgotPasswordCommand,
  InitiateAuthCommand,
  type PreventUserExistenceErrorTypes,
  ResendConfirmationCodeCommand,
  RespondToAuthChallengeCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { describe, expect, it } from "vitest";
import { srpClient } from "../../src/__tests__/srpClient";
import { withCognitoSdk } from "../aws-sdk/setup";

const PASSWORD = "Example-Passw0rd!";
const UNKNOWN = "nobody@example.test";
const credentials = { accessKeyId: "local", secretAccessKey: "local" };
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const newClient = (endpoint: string) =>
  new CognitoIdentityProviderClient({
    endpoint,
    region: "local",
    credentials,
    maxAttempts: 1,
  });

const setUp = async (
  cognito: CognitoIdentityProviderClient,
  prevent: PreventUserExistenceErrorTypes | undefined,
) => {
  const created = await cognito.send(
    new CreateUserPoolCommand({
      PoolName: "existence",
      AutoVerifiedAttributes: ["email"],
      Policies: {
        SignInPolicy: {
          AllowedFirstAuthFactors: ["PASSWORD", "EMAIL_OTP"],
        },
      },
    }),
  );
  const userPoolId = created.UserPool?.Id as string;
  const appClient = await cognito.send(
    new CreateUserPoolClientCommand({
      UserPoolId: userPoolId,
      ClientName: "existence",
      PreventUserExistenceErrors: prevent,
      ExplicitAuthFlows: [
        "ALLOW_USER_AUTH",
        "ALLOW_USER_PASSWORD_AUTH",
        "ALLOW_USER_SRP_AUTH",
        "ALLOW_ADMIN_USER_PASSWORD_AUTH",
        "ALLOW_CUSTOM_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
      ],
    }),
  );
  return { userPoolId, clientId: appClient.UserPoolClient?.ClientId as string };
};

describe(
  "PreventUserExistenceErrors",
  withCognitoSdk((_, { serverUrl, messageDelivery }) => {
    describe("ENABLED", () => {
      it("answers a password sign-in for an unknown user with the generic failure", async () => {
        const cognito = newClient(serverUrl());
        const { userPoolId, clientId } = await setUp(cognito, "ENABLED");

        await expect(
          cognito.send(
            new InitiateAuthCommand({
              AuthFlow: "USER_PASSWORD_AUTH",
              ClientId: clientId,
              AuthParameters: { USERNAME: UNKNOWN, PASSWORD },
            }),
          ),
        ).rejects.toMatchObject({
          name: "NotAuthorizedException",
          message: "Incorrect username or password.",
        });
        await expect(
          cognito.send(
            new AdminInitiateAuthCommand({
              AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
              UserPoolId: userPoolId,
              ClientId: clientId,
              AuthParameters: { USERNAME: UNKNOWN, PASSWORD },
            }),
          ),
        ).rejects.toMatchObject({
          name: "NotAuthorizedException",
          message: "Incorrect username or password.",
        });
      });

      it("simulates the SRP challenge with a stable salt and user id, then fails the proof", async () => {
        const cognito = newClient(serverUrl());
        const { userPoolId, clientId } = await setUp(cognito, "ENABLED");
        const start = () => {
          const srp = srpClient(userPoolId);
          return cognito
            .send(
              new InitiateAuthCommand({
                AuthFlow: "USER_SRP_AUTH",
                ClientId: clientId,
                AuthParameters: { USERNAME: UNKNOWN, SRP_A: srp.srpA },
              }),
            )
            .then((response) => ({ srp, response }));
        };

        const first = await start();
        const second = await start();
        expect(first.response.ChallengeName).toEqual("PASSWORD_VERIFIER");
        const params = first.response.ChallengeParameters ?? {};
        expect(params.USER_ID_FOR_SRP).toMatch(UUID_PATTERN);
        expect(params.SALT).toMatch(/^[0-9a-f]{32}$/);
        expect(params.SRP_B).toMatch(/^[0-9a-f]+$/);
        expect(params.SECRET_BLOCK).toBeDefined();
        expect(second.response.ChallengeParameters?.SALT).toEqual(params.SALT);
        expect(second.response.ChallengeParameters?.USER_ID_FOR_SRP).toEqual(
          params.USER_ID_FOR_SRP,
        );

        await expect(
          cognito.send(
            new RespondToAuthChallengeCommand({
              ClientId: clientId,
              ChallengeName: "PASSWORD_VERIFIER",
              Session: first.response.Session,
              ChallengeResponses: first.srp.respond(params, PASSWORD),
            }),
          ),
        ).rejects.toMatchObject({
          name: "NotAuthorizedException",
          message: "Incorrect username or password.",
        });
      });

      it("offers USER_AUTH challenges to an unknown user that never succeed", async () => {
        const cognito = newClient(serverUrl());
        const { clientId } = await setUp(cognito, "ENABLED");

        const select = await cognito.send(
          new InitiateAuthCommand({
            AuthFlow: "USER_AUTH",
            ClientId: clientId,
            AuthParameters: { USERNAME: UNKNOWN },
          }),
        );
        expect(select.ChallengeName).toEqual("SELECT_CHALLENGE");
        expect(select.AvailableChallenges).toEqual([
          "EMAIL_OTP",
          "PASSWORD",
          "PASSWORD_SRP",
        ]);

        const otp = await cognito.send(
          new RespondToAuthChallengeCommand({
            ClientId: clientId,
            ChallengeName: "SELECT_CHALLENGE",
            Session: select.Session,
            ChallengeResponses: { USERNAME: UNKNOWN, ANSWER: "EMAIL_OTP" },
          }),
        );
        expect(otp.ChallengeName).toEqual("EMAIL_OTP");
        expect(otp.ChallengeParameters).toEqual({
          CODE_DELIVERY_DELIVERY_MEDIUM: "EMAIL",
          CODE_DELIVERY_DESTINATION: UNKNOWN,
        });
        expect(messageDelivery().collectedMessages).toHaveLength(0);

        await expect(
          cognito.send(
            new RespondToAuthChallengeCommand({
              ClientId: clientId,
              ChallengeName: "EMAIL_OTP",
              Session: otp.Session,
              ChallengeResponses: {
                USERNAME: UNKNOWN,
                EMAIL_OTP_CODE: "123456",
              },
            }),
          ),
        ).rejects.toMatchObject({ name: "CodeMismatchException" });

        await expect(
          cognito.send(
            new InitiateAuthCommand({
              AuthFlow: "USER_AUTH",
              ClientId: clientId,
              AuthParameters: {
                USERNAME: UNKNOWN,
                PREFERRED_CHALLENGE: "PASSWORD",
                PASSWORD,
              },
            }),
          ),
        ).rejects.toMatchObject({
          name: "NotAuthorizedException",
          message: "Incorrect username or password.",
        });
      });

      it("hides RESET_REQUIRED behind the generic failure", async () => {
        const cognito = newClient(serverUrl());
        const { userPoolId, clientId } = await setUp(cognito, "ENABLED");
        await cognito.send(
          new AdminCreateUserCommand({
            UserPoolId: userPoolId,
            Username: "imported@example.test",
            MessageAction: "SUPPRESS",
          }),
        );
        await cognito.send(
          new AdminSetUserPasswordCommand({
            UserPoolId: userPoolId,
            Username: "imported@example.test",
            Password: PASSWORD,
            Permanent: true,
          }),
        );
        await cognito.send(
          new AdminResetUserPasswordCommand({
            UserPoolId: userPoolId,
            Username: "imported@example.test",
          }),
        );

        await expect(
          cognito.send(
            new InitiateAuthCommand({
              AuthFlow: "USER_PASSWORD_AUTH",
              ClientId: clientId,
              AuthParameters: {
                USERNAME: "imported@example.test",
                PASSWORD,
              },
            }),
          ),
        ).rejects.toMatchObject({
          name: "NotAuthorizedException",
          message: "Incorrect username or password.",
        });
      });

      it("returns simulated code delivery from ForgotPassword and ResendConfirmationCode", async () => {
        const cognito = newClient(serverUrl());
        const { clientId } = await setUp(cognito, "ENABLED");

        const forgot = await cognito.send(
          new ForgotPasswordCommand({ ClientId: clientId, Username: UNKNOWN }),
        );
        expect(forgot.CodeDeliveryDetails).toEqual({
          AttributeName: "email",
          DeliveryMedium: "EMAIL",
          Destination: UNKNOWN,
        });
        const resent = await cognito.send(
          new ResendConfirmationCodeCommand({
            ClientId: clientId,
            Username: UNKNOWN,
          }),
        );
        expect(resent.CodeDeliveryDetails).toEqual({
          AttributeName: "email",
          DeliveryMedium: "EMAIL",
          Destination: UNKNOWN,
        });
        expect(messageDelivery().collectedMessages).toHaveLength(0);
      });

      it("answers code confirmations for an unknown user with CodeMismatchException", async () => {
        const cognito = newClient(serverUrl());
        const { clientId } = await setUp(cognito, "ENABLED");

        await expect(
          cognito.send(
            new ConfirmForgotPasswordCommand({
              ClientId: clientId,
              Username: UNKNOWN,
              ConfirmationCode: "123456",
              Password: PASSWORD,
            }),
          ),
        ).rejects.toMatchObject({ name: "CodeMismatchException" });
        await expect(
          cognito.send(
            new ConfirmSignUpCommand({
              ClientId: clientId,
              Username: UNKNOWN,
              ConfirmationCode: "123456",
            }),
          ),
        ).rejects.toMatchObject({ name: "CodeMismatchException" });
      });
    });

    describe("LEGACY", () => {
      it("reports an unknown user with UserNotFoundException", async () => {
        const cognito = newClient(serverUrl());
        const { clientId } = await setUp(cognito, undefined);
        const notFound = {
          name: "UserNotFoundException",
          message: "User does not exist.",
        };

        await expect(
          cognito.send(
            new InitiateAuthCommand({
              AuthFlow: "USER_PASSWORD_AUTH",
              ClientId: clientId,
              AuthParameters: { USERNAME: UNKNOWN, PASSWORD },
            }),
          ),
        ).rejects.toMatchObject(notFound);
        await expect(
          cognito.send(
            new InitiateAuthCommand({
              AuthFlow: "USER_SRP_AUTH",
              ClientId: clientId,
              AuthParameters: { USERNAME: UNKNOWN, SRP_A: "abc123" },
            }),
          ),
        ).rejects.toMatchObject(notFound);
        await expect(
          cognito.send(
            new InitiateAuthCommand({
              AuthFlow: "USER_AUTH",
              ClientId: clientId,
              AuthParameters: { USERNAME: UNKNOWN },
            }),
          ),
        ).rejects.toMatchObject(notFound);
      });

      it("reports an unknown user to the code operations", async () => {
        const cognito = newClient(serverUrl());
        const { clientId } = await setUp(cognito, "LEGACY");
        const notFound = {
          name: "UserNotFoundException",
          message: "Username/client id combination not found.",
        };

        await expect(
          cognito.send(
            new ForgotPasswordCommand({
              ClientId: clientId,
              Username: UNKNOWN,
            }),
          ),
        ).rejects.toMatchObject(notFound);
        await expect(
          cognito.send(
            new ConfirmForgotPasswordCommand({
              ClientId: clientId,
              Username: UNKNOWN,
              ConfirmationCode: "123456",
              Password: PASSWORD,
            }),
          ),
        ).rejects.toMatchObject(notFound);
        await expect(
          cognito.send(
            new ResendConfirmationCodeCommand({
              ClientId: clientId,
              Username: UNKNOWN,
            }),
          ),
        ).rejects.toMatchObject(notFound);
        await expect(
          cognito.send(
            new ConfirmSignUpCommand({
              ClientId: clientId,
              Username: UNKNOWN,
              ConfirmationCode: "123456",
            }),
          ),
        ).rejects.toMatchObject(notFound);
      });
    });
  }),
);
