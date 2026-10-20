import {
  AdminAddUserToGroupCommand,
  AdminCreateUserCommand,
  AdminDeleteUserCommand,
  AdminDisableUserCommand,
  AdminEnableUserCommand,
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
  AdminRemoveUserFromGroupCommand,
  AdminSetUserPasswordCommand,
  AdminUpdateUserAttributesCommand,
  AliasExistsException,
  CognitoIdentityProviderClient,
  CognitoIdentityProviderServiceException,
  ConfirmForgotPasswordCommand,
  ConfirmSignUpCommand,
  CreateGroupCommand,
  CreateUserPoolClientCommand,
  CreateUserPoolCommand,
  DescribeUserPoolClientCommand,
  DescribeUserPoolCommand,
  ForgotPasswordCommand,
  GetUserCommand,
  GlobalSignOutCommand,
  InitiateAuthCommand,
  InvalidParameterException,
  InvalidPasswordException,
  ListUserPoolsCommand,
  ListUsersCommand,
  NotAuthorizedException,
  RespondToAuthChallengeCommand,
  SignUpCommand,
  UpdateUserAttributesCommand,
  UpdateUserPoolClientCommand,
  UserNotFoundException,
  UsernameExistsException,
} from "@aws-sdk/client-cognito-identity-provider";
import { afterEach, describe, expect, it } from "vitest";
import { LambdaService } from "../../src/services";
import { withCognitoSdk } from "../aws-sdk/setup";

const PASSWORD = "Passw0rd!";
const credentials = { accessKeyId: "local", secretAccessKey: "local" };

type TriggerEvent = {
  request: Record<string, any>;
  response: Record<string, any>;
};

const customAuthHandlers: Record<string, (event: TriggerEvent) => void> = {
  DefineAuthChallenge(event) {
    const last = event.request.session.at(-1);
    const passed =
      last?.challengeName === "CUSTOM_CHALLENGE" &&
      last.challengeResult === true;
    event.response.issueTokens = passed;
    event.response.failAuthentication = false;
    if (!passed) event.response.challengeName = "CUSTOM_CHALLENGE";
  },
  CreateAuthChallenge(event) {
    event.response.publicChallengeParameters = { hint: "code" };
    event.response.privateChallengeParameters = { answer: "123456" };
    event.response.challengeMetadata = "CODE";
  },
  VerifyAuthChallengeResponse(event) {
    event.response.answerCorrect =
      event.request.challengeAnswer ===
      event.request.privateChallengeParameters.answer;
  },
};

const customAuthLambda = () =>
  new LambdaService(
    {
      DefineAuthChallenge: "DefineAuthChallenge",
      CreateAuthChallenge: "CreateAuthChallenge",
      VerifyAuthChallengeResponse: "VerifyAuthChallengeResponse",
    },
    {
      invoke: (params: { FunctionName: string; Payload: string }) => ({
        promise: async () => {
          const event = JSON.parse(params.Payload);
          customAuthHandlers[params.FunctionName](event);
          return { StatusCode: 200, Payload: JSON.stringify(event) };
        },
      }),
    } as any,
  );

describe(
  "AWS SDK for JavaScript v3",
  withCognitoSdk(
    (_, { serverUrl, messageDelivery }) => {
      const client = () =>
        new CognitoIdentityProviderClient({
          region: "us-east-1",
          endpoint: serverUrl(),
          credentials,
        });

      const lastCode = () =>
        messageDelivery().collectedMessages.at(-1)?.message.__code as string;

      async function setup(
        poolOverrides: Partial<
          ConstructorParameters<typeof CreateUserPoolCommand>[0]
        > = {},
      ) {
        const cognito = client();
        const pool = await cognito.send(
          new CreateUserPoolCommand({
            PoolName: "v3",
            AutoVerifiedAttributes: ["email"],
            ...poolOverrides,
          }),
        );
        const UserPoolId = pool.UserPool!.Id!;
        const app = await cognito.send(
          new CreateUserPoolClientCommand({
            UserPoolId,
            ClientName: "web",
            ExplicitAuthFlows: [
              "ALLOW_USER_PASSWORD_AUTH",
              "ALLOW_CUSTOM_AUTH",
              "ALLOW_REFRESH_TOKEN_AUTH",
            ],
          }),
        );
        return { cognito, UserPoolId, ClientId: app.UserPoolClient!.ClientId! };
      }

      async function createConfirmedUser(
        cognito: CognitoIdentityProviderClient,
        UserPoolId: string,
        Username: string,
        email = `${Username}@example.test`,
      ) {
        await cognito.send(
          new AdminCreateUserCommand({
            UserPoolId,
            Username,
            MessageAction: "SUPPRESS",
            UserAttributes: [
              { Name: "email", Value: email },
              { Name: "email_verified", Value: "true" },
            ],
          }),
        );
        await cognito.send(
          new AdminSetUserPasswordCommand({
            UserPoolId,
            Username,
            Password: PASSWORD,
            Permanent: true,
          }),
        );
      }

      const passwordLogin = (
        cognito: CognitoIdentityProviderClient,
        ClientId: string,
        USERNAME: string,
        PASSWORD_ = PASSWORD,
      ) =>
        cognito.send(
          new InitiateAuthCommand({
            ClientId,
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: { USERNAME, PASSWORD: PASSWORD_ },
          }),
        );

      it("parses timestamps and the request id on a describe call", async () => {
        const { cognito, UserPoolId } = await setup();
        const pool = await cognito.send(
          new DescribeUserPoolCommand({ UserPoolId }),
        );
        expect(pool.$metadata.httpStatusCode).toBe(200);
        expect(pool.$metadata.requestId).toMatch(/^[0-9a-f-]{36}$/);
        expect(pool.UserPool?.CreationDate).toBeInstanceOf(Date);
        expect(pool.UserPool?.Name).toBe("v3");
      });

      it("keeps a client's AuthSessionValidity", async () => {
        const { cognito, UserPoolId, ClientId } = await setup();
        await cognito.send(
          new UpdateUserPoolClientCommand({
            UserPoolId,
            ClientId,
            AuthSessionValidity: 10,
          }),
        );
        const described = await cognito.send(
          new DescribeUserPoolClientCommand({ UserPoolId, ClientId }),
        );
        expect(described.UserPoolClient?.AuthSessionValidity).toBe(10);

        await expect(
          cognito.send(
            new UpdateUserPoolClientCommand({
              UserPoolId,
              ClientId,
              AuthSessionValidity: 20,
            }),
          ),
        ).rejects.toBeInstanceOf(InvalidParameterException);
      });

      it("signs up, confirms and signs in with USER_PASSWORD_AUTH", async () => {
        const { cognito, ClientId } = await setup();
        const signUp = await cognito.send(
          new SignUpCommand({
            ClientId,
            Username: "jane",
            Password: PASSWORD,
            UserAttributes: [{ Name: "email", Value: "jane@example.test" }],
          }),
        );
        expect(signUp.UserConfirmed).toBe(false);
        expect(signUp.UserSub).toBeTruthy();
        expect(signUp.CodeDeliveryDetails?.DeliveryMedium).toBe("EMAIL");

        await cognito.send(
          new ConfirmSignUpCommand({
            ClientId,
            Username: "jane",
            ConfirmationCode: lastCode(),
          }),
        );

        const auth = await passwordLogin(cognito, ClientId, "jane");
        expect(auth.AuthenticationResult?.AccessToken).toBeTruthy();
        expect(auth.AuthenticationResult?.IdToken).toBeTruthy();
        expect(auth.AuthenticationResult?.RefreshToken).toBeTruthy();

        const me = await cognito.send(
          new GetUserCommand({
            AccessToken: auth.AuthenticationResult!.AccessToken,
          }),
        );
        expect(me.Username).toBe("jane");
      });

      it("runs CUSTOM_AUTH through RespondToAuthChallenge", async () => {
        const { cognito, UserPoolId, ClientId } = await setup();
        await createConfirmedUser(cognito, UserPoolId, "alex");

        const start = await cognito.send(
          new InitiateAuthCommand({
            ClientId,
            AuthFlow: "CUSTOM_AUTH",
            AuthParameters: { USERNAME: "alex" },
          }),
        );
        expect(start.ChallengeName).toBe("CUSTOM_CHALLENGE");
        expect(start.ChallengeParameters).toMatchObject({ hint: "code" });
        expect(start.Session).toBeTruthy();

        const wrong = await cognito.send(
          new RespondToAuthChallengeCommand({
            ClientId,
            ChallengeName: "CUSTOM_CHALLENGE",
            Session: start.Session,
            ChallengeResponses: { USERNAME: "alex", ANSWER: "000000" },
          }),
        );
        expect(wrong.ChallengeName).toBe("CUSTOM_CHALLENGE");

        const done = await cognito.send(
          new RespondToAuthChallengeCommand({
            ClientId,
            ChallengeName: "CUSTOM_CHALLENGE",
            Session: wrong.Session,
            ChallengeResponses: { USERNAME: "alex", ANSWER: "123456" },
          }),
        );
        expect(done.AuthenticationResult?.AccessToken).toBeTruthy();
      });

      it("manages users and groups with Admin* operations", async () => {
        const { cognito, UserPoolId } = await setup();
        await createConfirmedUser(cognito, UserPoolId, "sam");
        await cognito.send(
          new CreateGroupCommand({
            UserPoolId,
            GroupName: "editors",
            Precedence: 1,
          }),
        );
        await cognito.send(
          new AdminAddUserToGroupCommand({
            UserPoolId,
            Username: "sam",
            GroupName: "editors",
          }),
        );
        const groups = await cognito.send(
          new AdminListGroupsForUserCommand({ UserPoolId, Username: "sam" }),
        );
        expect(groups.Groups?.map((g) => g.GroupName)).toEqual(["editors"]);
        expect(groups.Groups?.[0].CreationDate).toBeInstanceOf(Date);

        await cognito.send(
          new AdminRemoveUserFromGroupCommand({
            UserPoolId,
            Username: "sam",
            GroupName: "editors",
          }),
        );
        await cognito.send(
          new AdminUpdateUserAttributesCommand({
            UserPoolId,
            Username: "sam",
            UserAttributes: [{ Name: "name", Value: "Sam" }],
          }),
        );
        await cognito.send(
          new AdminDisableUserCommand({ UserPoolId, Username: "sam" }),
        );
        const disabled = await cognito.send(
          new AdminGetUserCommand({ UserPoolId, Username: "sam" }),
        );
        expect(disabled.Enabled).toBe(false);
        expect(disabled.UserStatus).toBe("CONFIRMED");
        expect(disabled.UserCreateDate).toBeInstanceOf(Date);
        expect(disabled.UserAttributes).toContainEqual({
          Name: "name",
          Value: "Sam",
        });

        await cognito.send(
          new AdminEnableUserCommand({ UserPoolId, Username: "sam" }),
        );
        await cognito.send(
          new AdminDeleteUserCommand({ UserPoolId, Username: "sam" }),
        );
        const missing = await cognito
          .send(new AdminGetUserCommand({ UserPoolId, Username: "sam" }))
          .catch((e) => e);
        expect(missing).toBeInstanceOf(UserNotFoundException);
        expect(missing.name).toBe("UserNotFoundException");
        expect(missing.$metadata.httpStatusCode).toBe(400);
      });

      it("resets a password with ForgotPassword and ConfirmForgotPassword", async () => {
        const { cognito, UserPoolId, ClientId } = await setup();
        await createConfirmedUser(cognito, UserPoolId, "pat");

        const forgot = await cognito.send(
          new ForgotPasswordCommand({ ClientId, Username: "pat" }),
        );
        expect(forgot.CodeDeliveryDetails?.DeliveryMedium).toBe("EMAIL");

        await cognito.send(
          new ConfirmForgotPasswordCommand({
            ClientId,
            Username: "pat",
            ConfirmationCode: lastCode(),
            Password: "N3w-Passw0rd!",
          }),
        );
        const auth = await passwordLogin(
          cognito,
          ClientId,
          "pat",
          "N3w-Passw0rd!",
        );
        expect(auth.AuthenticationResult?.AccessToken).toBeTruthy();
      });

      it("filters ListUsers", async () => {
        const { cognito, UserPoolId } = await setup();
        await createConfirmedUser(cognito, UserPoolId, "first");
        await createConfirmedUser(cognito, UserPoolId, "second");

        const users = await cognito.send(
          new ListUsersCommand({
            UserPoolId,
            Filter: 'email = "second@example.test"',
          }),
        );
        expect(users.Users?.map((u) => u.Username)).toEqual(["second"]);
        expect(users.Users?.[0].UserLastModifiedDate).toBeInstanceOf(Date);
      });

      it("updates attributes with an access token and signs out globally", async () => {
        const { cognito, UserPoolId, ClientId } = await setup();
        await createConfirmedUser(cognito, UserPoolId, "kim");
        const auth = await passwordLogin(cognito, ClientId, "kim");
        const AccessToken = auth.AuthenticationResult!.AccessToken!;

        await cognito.send(
          new UpdateUserAttributesCommand({
            AccessToken,
            UserAttributes: [{ Name: "name", Value: "Kim" }],
          }),
        );
        const me = await cognito.send(new GetUserCommand({ AccessToken }));
        expect(me.UserAttributes).toContainEqual({
          Name: "name",
          Value: "Kim",
        });

        await cognito.send(new GlobalSignOutCommand({ AccessToken }));
        const refresh = await cognito
          .send(
            new InitiateAuthCommand({
              ClientId,
              AuthFlow: "REFRESH_TOKEN_AUTH",
              AuthParameters: {
                REFRESH_TOKEN: auth.AuthenticationResult!.RefreshToken!,
              },
            }),
          )
          .catch((e) => e);
        expect(refresh).toBeInstanceOf(NotAuthorizedException);
      });

      describe("errors surface as the modeled v3 exception classes", () => {
        const expectException = (
          error: unknown,
          type: new (...args: any[]) => CognitoIdentityProviderServiceException,
          name: string,
        ) => {
          expect(error).toBeInstanceOf(type);
          expect(error).toBeInstanceOf(CognitoIdentityProviderServiceException);
          const e = error as CognitoIdentityProviderServiceException;
          expect(e.name).toBe(name);
          expect(e.$fault).toBe("client");
          expect(e.$metadata.httpStatusCode).toBe(400);
          expect(e.$metadata.requestId).toBeTruthy();
          expect(e.message).toBeTruthy();
        };

        it("UsernameExistsException", async () => {
          const { cognito, UserPoolId } = await setup();
          await createConfirmedUser(cognito, UserPoolId, "dup");
          const error = await createConfirmedUser(
            cognito,
            UserPoolId,
            "dup",
          ).catch((e) => e);
          expectException(
            error,
            UsernameExistsException,
            "UsernameExistsException",
          );
        });

        it("NotAuthorizedException", async () => {
          const { cognito, UserPoolId, ClientId } = await setup();
          await createConfirmedUser(cognito, UserPoolId, "lee");
          const error = await passwordLogin(
            cognito,
            ClientId,
            "lee",
            "Wr0ng-password",
          ).catch((e) => e);
          expectException(
            error,
            NotAuthorizedException,
            "NotAuthorizedException",
          );
        });

        it("AliasExistsException", async () => {
          const { cognito, UserPoolId } = await setup({
            AliasAttributes: ["email"],
          });
          await createConfirmedUser(
            cognito,
            UserPoolId,
            "one",
            "shared@example.test",
          );
          const error = await createConfirmedUser(
            cognito,
            UserPoolId,
            "two",
            "shared@example.test",
          ).catch((e) => e);
          expectException(error, AliasExistsException, "AliasExistsException");
        });

        it("InvalidPasswordException", async () => {
          const { cognito, ClientId } = await setup();
          const error = await cognito
            .send(
              new SignUpCommand({
                ClientId,
                Username: "weak",
                Password: "short",
                UserAttributes: [{ Name: "email", Value: "weak@example.test" }],
              }),
            )
            .catch((e) => e);
          expectException(
            error,
            InvalidPasswordException,
            "InvalidPasswordException",
          );
        });
      });

      describe("endpoint from the environment", () => {
        const saved = process.env.AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER;
        afterEach(() => {
          if (saved === undefined) {
            delete process.env.AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER;
          } else {
            process.env.AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER = saved;
          }
        });

        it("reads AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER", async () => {
          await setup();
          process.env.AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER = serverUrl();
          const fromEnv = new CognitoIdentityProviderClient({
            region: "us-east-1",
            credentials,
          });
          const pools = await fromEnv.send(
            new ListUserPoolsCommand({ MaxResults: 10 }),
          );
          expect(pools.UserPools?.map((p) => p.Name)).toEqual(["v3"]);
        });
      });
    },
    { lambda: customAuthLambda },
  ),
);
