import type { CognitoIdentityServiceProvider } from "aws-sdk";
import { describe, expect, it } from "vitest";
import { LambdaService } from "../../src/services";
import { withCognitoSdk } from "./setup";

const PASSWORD = "Passw0rd!";
const PHONE = "+972501234567";

const attr = (
  user: CognitoIdentityServiceProvider.AdminGetUserResponse,
  name: string,
) => user.UserAttributes?.find((a) => a.Name === name)?.Value;

const freeFormUsernamePool = async (client: CognitoIdentityServiceProvider) => {
  const pool = await client
    .createUserPool({
      PoolName: "test",
      AliasAttributes: ["phone_number", "preferred_username"],
      UsernameAttributes: [],
      AutoVerifiedAttributes: ["email"],
    })
    .promise();
  const userPoolId = pool.UserPool?.Id as string;
  const client_ = await client
    .createUserPoolClient({ UserPoolId: userPoolId, ClientName: "app" })
    .promise();
  return {
    userPoolId,
    clientId: client_.UserPoolClient?.ClientId as string,
  };
};

const createVerifiedPhoneUser = (
  client: CognitoIdentityServiceProvider,
  userPoolId: string,
  username: string,
  extra: Partial<CognitoIdentityServiceProvider.AdminCreateUserRequest> = {},
) =>
  client
    .adminCreateUser({
      UserPoolId: userPoolId,
      Username: username,
      MessageAction: "SUPPRESS",
      UserAttributes: [
        { Name: "phone_number", Value: PHONE },
        { Name: "phone_number_verified", Value: "true" },
      ],
      ...extra,
    })
    .promise();

describe(
  "CognitoIdentityServiceProvider aliases",
  withCognitoSdk((Cognito, { messageDelivery }) => {
    it("AdminCreateUser throws AliasExistsException for a verified phone another user has", async () => {
      const client = Cognito();
      const { userPoolId } = await freeFormUsernamePool(client);
      await createVerifiedPhoneUser(client, userPoolId, "first");

      await expect(
        createVerifiedPhoneUser(client, userPoolId, "dup-phone"),
      ).rejects.toMatchObject({
        code: "AliasExistsException",
        message: "An account with the given phone_number already exists.",
      });
    });

    it("AdminCreateUser with ForceAliasCreation moves the alias", async () => {
      const client = Cognito();
      const { userPoolId } = await freeFormUsernamePool(client);
      await createVerifiedPhoneUser(client, userPoolId, "first");

      await createVerifiedPhoneUser(client, userPoolId, "second", {
        ForceAliasCreation: true,
      });

      const first = await client
        .adminGetUser({ UserPoolId: userPoolId, Username: "first" })
        .promise();
      const second = await client
        .adminGetUser({ UserPoolId: userPoolId, Username: "second" })
        .promise();
      expect(attr(first, "phone_number")).toEqual(PHONE);
      expect(attr(first, "phone_number_verified")).toEqual("false");
      expect(attr(second, "phone_number_verified")).toEqual("true");
    });

    it("SignUp accepts a duplicate phone, and verifying it with AdminUpdateUserAttributes throws AliasExistsException", async () => {
      const client = Cognito();
      const { userPoolId, clientId } = await freeFormUsernamePool(client);
      await createVerifiedPhoneUser(client, userPoolId, "first");

      const signUp = await client
        .signUp({
          ClientId: clientId,
          Username: "visitor",
          Password: PASSWORD,
          UserAttributes: [
            { Name: "phone_number", Value: PHONE },
            { Name: "email", Value: "visitor@example.com" },
          ],
        })
        .promise();
      expect(signUp.UserConfirmed).toBe(false);

      await expect(
        client
          .adminUpdateUserAttributes({
            UserPoolId: userPoolId,
            Username: "visitor",
            UserAttributes: [{ Name: "phone_number_verified", Value: "true" }],
          })
          .promise(),
      ).rejects.toMatchObject({ code: "AliasExistsException" });
    });

    it("AdminUpdateUserAttributes accepts email_verified on its own", async () => {
      const client = Cognito();
      const { userPoolId } = await freeFormUsernamePool(client);
      await client
        .adminCreateUser({
          UserPoolId: userPoolId,
          Username: "gov",
          MessageAction: "SUPPRESS",
          UserAttributes: [{ Name: "email", Value: "gov@example.com" }],
        })
        .promise();

      await client
        .adminUpdateUserAttributes({
          UserPoolId: userPoolId,
          Username: "gov",
          UserAttributes: [{ Name: "email_verified", Value: "true" }],
        })
        .promise();

      const user = await client
        .adminGetUser({ UserPoolId: userPoolId, Username: "gov" })
        .promise();
      expect(attr(user, "email_verified")).toEqual("true");
    });

    it("UpdateUserAttributes throws AliasExistsException for a taken preferred_username", async () => {
      const client = Cognito();
      const { userPoolId, clientId } = await freeFormUsernamePool(client);
      await client
        .adminCreateUser({
          UserPoolId: userPoolId,
          Username: "first",
          MessageAction: "SUPPRESS",
          UserAttributes: [{ Name: "preferred_username", Value: "jane" }],
        })
        .promise();
      await client
        .adminCreateUser({
          UserPoolId: userPoolId,
          Username: "second",
          MessageAction: "SUPPRESS",
        })
        .promise();
      await client
        .adminSetUserPassword({
          UserPoolId: userPoolId,
          Username: "second",
          Password: PASSWORD,
          Permanent: true,
        })
        .promise();
      const auth = await client
        .initiateAuth({
          AuthFlow: "USER_PASSWORD_AUTH",
          ClientId: clientId,
          AuthParameters: { USERNAME: "second", PASSWORD },
        })
        .promise();

      await expect(
        client
          .updateUserAttributes({
            AccessToken: auth.AuthenticationResult?.AccessToken as string,
            UserAttributes: [{ Name: "preferred_username", Value: "jane" }],
          })
          .promise(),
      ).rejects.toMatchObject({
        code: "AliasExistsException",
        message: "An account with the given preferred_username already exists.",
      });
    });

    describe("email alias confirmed with ConfirmSignUp", () => {
      const EMAIL = "jane@example.com";

      const emailAliasPool = async (client: CognitoIdentityServiceProvider) => {
        const pool = await client
          .createUserPool({
            PoolName: "test",
            AliasAttributes: ["email"],
            AutoVerifiedAttributes: ["email"],
          })
          .promise();
        const userPoolId = pool.UserPool?.Id as string;
        const upc = await client
          .createUserPoolClient({ UserPoolId: userPoolId, ClientName: "app" })
          .promise();
        return {
          userPoolId,
          clientId: upc.UserPoolClient?.ClientId as string,
        };
      };

      const signUpAndGetCode = async (
        client: CognitoIdentityServiceProvider,
        clientId: string,
        username: string,
      ) => {
        await client
          .signUp({
            ClientId: clientId,
            Username: username,
            Password: PASSWORD,
            UserAttributes: [{ Name: "email", Value: EMAIL }],
          })
          .promise();
        return messageDelivery().collectedMessages.at(-1)?.message
          .__code as string;
      };

      it("throws AliasExistsException, then moves the alias with ForceAliasCreation", async () => {
        const client = Cognito();
        const { userPoolId, clientId } = await emailAliasPool(client);

        const firstCode = await signUpAndGetCode(client, clientId, "first");
        await client
          .confirmSignUp({
            ClientId: clientId,
            Username: "first",
            ConfirmationCode: firstCode,
          })
          .promise();

        const secondCode = await signUpAndGetCode(client, clientId, "second");
        await expect(
          client
            .confirmSignUp({
              ClientId: clientId,
              Username: "second",
              ConfirmationCode: secondCode,
            })
            .promise(),
        ).rejects.toMatchObject({
          code: "AliasExistsException",
          message: "An account with the given email already exists.",
        });

        await client
          .confirmSignUp({
            ClientId: clientId,
            Username: "second",
            ConfirmationCode: secondCode,
            ForceAliasCreation: true,
          })
          .promise();

        const first = await client
          .adminGetUser({ UserPoolId: userPoolId, Username: "first" })
          .promise();
        const second = await client
          .adminGetUser({ UserPoolId: userPoolId, Username: "second" })
          .promise();
        expect(attr(first, "email_verified")).toEqual("false");
        expect(second.UserStatus).toEqual("CONFIRMED");
        expect(attr(second, "email_verified")).toEqual("true");
      });
    });

    it("SignUp throws UsernameExistsException for an email already used as a username attribute", async () => {
      const client = Cognito();
      const pool = await client
        .createUserPool({ PoolName: "test", UsernameAttributes: ["email"] })
        .promise();
      const upc = await client
        .createUserPoolClient({
          UserPoolId: pool.UserPool?.Id as string,
          ClientName: "app",
        })
        .promise();
      const clientId = upc.UserPoolClient?.ClientId as string;
      await client
        .signUp({
          ClientId: clientId,
          Username: "a@example.com",
          Password: PASSWORD,
        })
        .promise();

      await expect(
        client
          .signUp({
            ClientId: clientId,
            Username: "a@example.com",
            Password: PASSWORD,
          })
          .promise(),
      ).rejects.toMatchObject({
        code: "UsernameExistsException",
        message: "An account with the given email already exists.",
      });
    });
  }),
);

const autoConfirmLambda = () =>
  new LambdaService({ PreSignUp: "PreSignUp" }, {
    invoke: (params: { FunctionName: string; Payload: string }) => ({
      promise: async () => {
        const event = JSON.parse(params.Payload);
        event.response = {
          autoConfirmUser: true,
          autoVerifyPhone: "phone_number" in event.request.userAttributes,
          autoVerifyEmail: "email" in event.request.userAttributes,
        };
        return { StatusCode: 200, Payload: JSON.stringify(event) };
      },
    }),
  } as any);

describe(
  "CognitoIdentityServiceProvider aliases with a PreSignUp trigger",
  withCognitoSdk(
    (Cognito, { messageDelivery }) => {
      it("auto-confirms a phone-only visitor without sending a code, and moves the phone alias", async () => {
        const client = Cognito();
        const { userPoolId, clientId } = await freeFormUsernamePool(client);
        const signUp = (username: string) =>
          client
            .signUp({
              ClientId: clientId,
              Username: username,
              Password: PASSWORD,
              UserAttributes: [
                { Name: "name", Value: "visitor" },
                { Name: "phone_number", Value: PHONE },
              ],
            })
            .promise();

        const first = await signUp("otp_first");
        expect(first.UserConfirmed).toBe(true);
        expect(first.CodeDeliveryDetails).toBeUndefined();
        expect(messageDelivery().collectedMessages).toHaveLength(0);

        await signUp("otp_second");

        const firstUser = await client
          .adminGetUser({ UserPoolId: userPoolId, Username: "otp_first" })
          .promise();
        const secondUser = await client
          .adminGetUser({ UserPoolId: userPoolId, Username: "otp_second" })
          .promise();
        expect(attr(firstUser, "phone_number_verified")).toEqual("false");
        expect(secondUser.UserStatus).toEqual("CONFIRMED");
        expect(attr(secondUser, "phone_number_verified")).toEqual("true");
      });
    },
    { lambda: autoConfirmLambda },
  ),
);
