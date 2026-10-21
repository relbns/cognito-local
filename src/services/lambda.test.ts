import {
  beforeEach,
  describe,
  expect,
  it,
  type MockedObject,
  vi,
} from "vitest";
import { TestContext } from "../__tests__/testContext";
import {
  InvalidLambdaResponseError,
  UserLambdaValidationError,
} from "../errors";
import { type LambdaClient, LambdaService } from "./lambda";

const encode = (text: string) => new TextEncoder().encode(text);

const invokedWith = (client: MockedObject<LambdaClient>) => {
  const [params] = client.invoke.mock.calls[0];
  return {
    ...params,
    Payload: JSON.parse(new TextDecoder().decode(params.Payload as Uint8Array)),
  };
};

describe("Lambda function invoker", () => {
  let mockLambdaClient: MockedObject<LambdaClient>;

  beforeEach(() => {
    mockLambdaClient = {
      invoke: vi.fn(),
    } as any;
  });

  describe("enabled", () => {
    it("returns true if lambda is configured", () => {
      const lambda = new LambdaService(
        {
          UserMigration: "MyLambdaName",
        },
        mockLambdaClient,
      );

      expect(lambda.enabled("UserMigration")).toBe(true);
    });

    it("returns false if lambda is not configured", () => {
      const lambda = new LambdaService({}, mockLambdaClient);

      expect(lambda.enabled("UserMigration")).toBe(false);
    });
  });

  describe("invoke", () => {
    it("throws if lambda is not configured", async () => {
      const lambda = new LambdaService({}, mockLambdaClient);

      await expect(
        lambda.invoke(TestContext, "UserMigration", {
          clientId: "clientId",
          clientMetadata: undefined,
          password: "password",
          triggerSource: "UserMigration_Authentication",
          userAttributes: {},
          username: "username",
          userPoolId: "userPoolId",
          validationData: undefined,
        }),
      ).rejects.toEqual(new Error("UserMigration trigger not configured"));
    });

    describe("when lambda is successful", () => {
      it("returns string payload as json", async () => {
        const response = Promise.resolve({
          StatusCode: 200,
          Payload: encode('{ "response": { "ok": "value" } }'),
        });
        mockLambdaClient.invoke.mockReturnValue(response as any);
        const lambda = new LambdaService(
          {
            UserMigration: "MyLambdaName",
          },
          mockLambdaClient,
        );

        const result = await lambda.invoke(TestContext, "UserMigration", {
          clientId: "clientId",
          clientMetadata: undefined,
          password: "password",
          triggerSource: "UserMigration_Authentication",
          userAttributes: {},
          username: "username",
          userPoolId: "userPoolId",
          validationData: undefined,
        });

        expect(result).toEqual({ ok: "value" });
      });

      it("throws if an invalid payload is returned", async () => {
        const response = Promise.resolve({
          StatusCode: 200,
          Payload: encode('{ "respo...'),
        });
        mockLambdaClient.invoke.mockReturnValue(response as any);
        const lambda = new LambdaService(
          {
            UserMigration: "MyLambdaName",
          },
          mockLambdaClient,
        );

        await expect(
          lambda.invoke(TestContext, "UserMigration", {
            clientId: "clientId",
            clientMetadata: undefined,
            password: "password",
            triggerSource: "UserMigration_Authentication",
            userAttributes: {},
            username: "username",
            userPoolId: "userPoolId",
            validationData: undefined,
          }),
        ).rejects.toBeInstanceOf(InvalidLambdaResponseError);
      });

      it("throws if the function returns an error", async () => {
        const response = Promise.resolve({
          StatusCode: 500,
          FunctionError: "Something bad happened",
        });
        mockLambdaClient.invoke.mockReturnValue(response as any);
        const lambda = new LambdaService(
          {
            UserMigration: "MyLambdaName",
          },
          mockLambdaClient,
        );

        await expect(
          lambda.invoke(TestContext, "UserMigration", {
            clientId: "clientId",
            clientMetadata: undefined,
            password: "password",
            triggerSource: "UserMigration_Authentication",
            userAttributes: {},
            username: "username",
            userPoolId: "userPoolId",
            validationData: undefined,
          }),
        ).rejects.toEqual(
          new UserLambdaValidationError("Something bad happened"),
        );
      });

      it("throws if the function returns an Unhandled error with a 200 status code and a errorMessage payload", async () => {
        // this seems to happen whenever userland code throws an error which isn't handled
        const response = Promise.resolve({
          StatusCode: 200,
          FunctionError: "Unhandled",
          Payload: encode('{"errorMessage":"Something bad in Userland"}'),
        });
        mockLambdaClient.invoke.mockReturnValue(response as any);
        const lambda = new LambdaService(
          {
            UserMigration: "MyLambdaName",
          },
          mockLambdaClient,
        );

        await expect(
          lambda.invoke(TestContext, "UserMigration", {
            clientId: "clientId",
            clientMetadata: undefined,
            password: "password",
            triggerSource: "UserMigration_Authentication",
            userAttributes: {},
            username: "username",
            userPoolId: "userPoolId",
            validationData: undefined,
          }),
        ).rejects.toEqual(
          new UserLambdaValidationError(
            "UserMigration failed with error Something bad in Userland.",
          ),
        );
      });

      it("returns Buffer payload as json", async () => {
        const response = Promise.resolve({
          StatusCode: 200,
          Payload: Buffer.from('{ "response": "value" }'),
        });
        mockLambdaClient.invoke.mockReturnValue(response as any);
        const lambda = new LambdaService(
          {
            UserMigration: "MyLambdaName",
          },
          mockLambdaClient,
        );

        const result = await lambda.invoke(TestContext, "UserMigration", {
          clientId: "clientId",
          clientMetadata: undefined,
          password: "password",
          triggerSource: "UserMigration_Authentication",
          userAttributes: {},
          username: "username",
          userPoolId: "userPoolId",
          validationData: undefined,
        });

        expect(result).toEqual("value");
      });
    });

    describe.each([
      "PreSignUp_AdminCreateUser",
      "PreSignUp_ExternalProvider",
      "PreSignUp_SignUp",
    ] as const)("%s", (source) => {
      it("invokes the lambda", async () => {
        const response = Promise.resolve({
          StatusCode: 200,
          Payload: encode('{ "some": "json" }'),
        });
        mockLambdaClient.invoke.mockReturnValue(response as any);
        const lambda = new LambdaService(
          {
            PreSignUp: "MyLambdaName",
          },
          mockLambdaClient,
        );

        await lambda.invoke(TestContext, "PreSignUp", {
          clientId: "clientId",
          clientMetadata: {
            client: "metadata",
          },
          triggerSource: source,
          username: "username",
          userPoolId: "userPoolId",
          userAttributes: {},
          validationData: {
            validation: "data",
          },
        });

        expect(invokedWith(mockLambdaClient)).toEqual({
          FunctionName: "MyLambdaName",
          InvocationType: "RequestResponse",
          Payload: {
            version: "0",
            callerContext: {
              awsSdkVersion: "aws-sdk-unknown-unknown",
              clientId: "clientId",
            },
            region: "local",
            userPoolId: "userPoolId",
            triggerSource: source,
            request: {
              clientMetadata: {
                client: "metadata",
              },
              userAttributes: {},
              validationData: {
                validation: "data",
              },
            },
            response: {
              autoConfirmUser: false,
              autoVerifyEmail: false,
              autoVerifyPhone: false,
            },
            userName: "username",
          },
        });
      });
    });

    describe("UserMigration_Authentication", () => {
      it("invokes the lambda", async () => {
        const response = Promise.resolve({
          StatusCode: 200,
          Payload: encode('{ "some": "json" }'),
        });
        mockLambdaClient.invoke.mockReturnValue(response as any);
        const lambda = new LambdaService(
          {
            UserMigration: "MyLambdaName",
          },
          mockLambdaClient,
        );

        await lambda.invoke(TestContext, "UserMigration", {
          clientId: "clientId",
          clientMetadata: {
            client: "metadata",
          },
          password: "password",
          triggerSource: "UserMigration_Authentication",
          username: "username",
          userPoolId: "userPoolId",
          userAttributes: {},
          validationData: {
            validation: "data",
          },
        });

        expect(invokedWith(mockLambdaClient)).toEqual({
          FunctionName: "MyLambdaName",
          InvocationType: "RequestResponse",
          Payload: {
            version: "0",
            callerContext: {
              awsSdkVersion: "aws-sdk-unknown-unknown",
              clientId: "clientId",
            },
            region: "local",
            userPoolId: "userPoolId",
            triggerSource: "UserMigration_Authentication",
            request: {
              clientMetadata: {
                client: "metadata",
              },
              password: "password",
              validationData: {
                validation: "data",
              },
            },
            response: {
              desiredDeliveryMediums: [],
              userAttributes: {},
            },
            userName: "username",
          },
        });
      });
    });

    describe.each`
      trigger                 | source
      ${"PostAuthentication"} | ${"PostAuthentication_Authentication"}
    `("$source", ({ trigger, source }) => {
      it("invokes the lambda", async () => {
        const response = Promise.resolve({
          StatusCode: 200,
          Payload: encode('{ "some": "json" }'),
        });
        mockLambdaClient.invoke.mockReturnValue(response as any);
        const lambda = new LambdaService(
          {
            [trigger]: "MyLambdaName",
          },
          mockLambdaClient,
        );

        await lambda.invoke(TestContext, trigger, {
          clientId: "clientId",
          triggerSource: source,
          username: "username",
          userPoolId: "userPoolId",
          userAttributes: {
            user: "attributes",
          },
          clientMetadata: {
            client: "metadata",
          },
        });

        expect(invokedWith(mockLambdaClient)).toEqual({
          FunctionName: "MyLambdaName",
          InvocationType: "RequestResponse",
          Payload: {
            version: "0",
            callerContext: {
              awsSdkVersion: "aws-sdk-unknown-unknown",
              clientId: "clientId",
            },
            region: "local",
            userPoolId: "userPoolId",
            triggerSource: source,
            request: {
              userAttributes: {
                user: "attributes",
              },
              clientMetadata: {
                client: "metadata",
              },
              newDeviceUsed: false,
            },
            response: {},
            userName: "username",
          },
        });
      });
    });

    describe("CustomSMSSender", () => {
      it("sends a customSMSSenderRequestV1 event with the encrypted code", async () => {
        mockLambdaClient.invoke.mockReturnValue(
          Promise.resolve({
            StatusCode: 200,
            Payload: encode('{ "response": {} }'),
          }) as any,
        );
        const lambda = new LambdaService(
          { CustomSMSSender: "MyLambdaName" },
          mockLambdaClient,
        );

        await lambda.invoke(TestContext, "CustomSMSSender", {
          clientId: "clientId",
          clientMetadata: { client: "metadata" },
          code: "encrypted",
          triggerSource: "CustomSMSSender_Authentication",
          username: "username",
          userPoolId: "userPoolId",
          userAttributes: { phone_number: "+15555550100" },
        });

        expect(invokedWith(mockLambdaClient).Payload).toEqual({
          version: "0",
          callerContext: {
            awsSdkVersion: "aws-sdk-unknown-unknown",
            clientId: "clientId",
          },
          region: "local",
          userPoolId: "userPoolId",
          triggerSource: "CustomSMSSender_Authentication",
          request: {
            type: "customSMSSenderRequestV1",
            code: "encrypted",
            userAttributes: { phone_number: "+15555550100" },
            clientMetadata: { client: "metadata" },
          },
          response: {},
          userName: "username",
        });
      });
    });

    describe("PreAuthentication_Authentication", () => {
      it.each([
        [undefined, {}],
        [true, { userNotFound: true }],
      ])(
        "sends the event with userNotFound=%s",
        async (userNotFound, extra) => {
          mockLambdaClient.invoke.mockReturnValue(
            Promise.resolve({
              StatusCode: 200,
              Payload: encode('{ "response": {} }'),
            }) as any,
          );
          const lambda = new LambdaService(
            { PreAuthentication: "MyLambdaName" },
            mockLambdaClient,
          );

          await lambda.invoke(TestContext, "PreAuthentication", {
            clientId: "clientId",
            triggerSource: "PreAuthentication_Authentication",
            username: "username",
            userPoolId: "userPoolId",
            userAttributes: { user: "attributes" },
            userNotFound,
            validationData: { client: "metadata" },
          });

          expect(invokedWith(mockLambdaClient).Payload).toEqual({
            version: "0",
            callerContext: {
              awsSdkVersion: "aws-sdk-unknown-unknown",
              clientId: "clientId",
            },
            region: "local",
            userPoolId: "userPoolId",
            triggerSource: "PreAuthentication_Authentication",
            request: {
              userAttributes: { user: "attributes" },
              validationData: { client: "metadata" },
              ...extra,
            },
            response: {},
            userName: "username",
          });
        },
      );
    });

    describe.each`
      trigger               | source
      ${"PostConfirmation"} | ${"PostConfirmation_ConfirmSignUp"}
      ${"PostConfirmation"} | ${"PostConfirmation_ConfirmForgotPassword"}
    `("$source", ({ trigger, source }) => {
      it("invokes the lambda", async () => {
        const response = Promise.resolve({
          StatusCode: 200,
          Payload: encode('{ "some": "json" }'),
        });
        mockLambdaClient.invoke.mockReturnValue(response as any);
        const lambda = new LambdaService(
          {
            [trigger]: "MyLambdaName",
          },
          mockLambdaClient,
        );

        await lambda.invoke(TestContext, trigger, {
          clientId: "clientId",
          triggerSource: source,
          username: "username",
          userPoolId: "userPoolId",
          userAttributes: {
            user: "attributes",
          },
          clientMetadata: {
            client: "metadata",
          },
        });

        expect(invokedWith(mockLambdaClient)).toEqual({
          FunctionName: "MyLambdaName",
          InvocationType: "RequestResponse",
          Payload: {
            version: "0",
            callerContext: {
              awsSdkVersion: "aws-sdk-unknown-unknown",
              clientId: "clientId",
            },
            region: "local",
            userPoolId: "userPoolId",
            triggerSource: source,
            request: {
              userAttributes: {
                user: "attributes",
              },
              clientMetadata: {
                client: "metadata",
              },
            },
            response: {},
            userName: "username",
          },
        });
      });
    });

    describe.each`
      trigger              | source
      ${"TokenGeneration"} | ${"TokenGeneration_AuthenticateDevice"}
      ${"TokenGeneration"} | ${"TokenGeneration_Authentication"}
      ${"TokenGeneration"} | ${"TokenGeneration_HostedAuth"}
      ${"TokenGeneration"} | ${"TokenGeneration_NewPasswordChallenge"}
      ${"TokenGeneration"} | ${"TokenGeneration_RefreshTokens"}
    `("$source", ({ trigger, source }) => {
      const groupConfiguration = {
        groupsToOverride: ["admins"],
        iamRolesToOverride: ["arn:aws:iam::000000000000:role/admins"],
        preferredRole: "arn:aws:iam::000000000000:role/admins",
      };
      const invoke = async (version: "1" | "2" | "3") => {
        const response = Promise.resolve({
          StatusCode: 200,
          Payload: encode('{ "some": "json" }'),
        });
        mockLambdaClient.invoke.mockReturnValue(response as any);
        const lambda = new LambdaService(
          {
            [trigger]: "MyLambdaName",
          },
          mockLambdaClient,
        );

        await lambda.invoke(TestContext, trigger, {
          clientId: "clientId",
          triggerSource: source,
          username: "username",
          userPoolId: "userPoolId",
          userAttributes: {
            user: "attributes",
          },
          clientMetadata: {
            client: "metadata",
          },
          groupConfiguration,
          scopes: ["aws.cognito.signin.user.admin"],
          version,
        });
        return invokedWith(mockLambdaClient);
      };

      it("invokes the lambda with a version 1 event", async () => {
        expect(await invoke("1")).toEqual({
          FunctionName: "MyLambdaName",
          InvocationType: "RequestResponse",
          Payload: {
            version: "1",
            callerContext: {
              awsSdkVersion: "aws-sdk-unknown-unknown",
              clientId: "clientId",
            },
            region: "local",
            userPoolId: "userPoolId",
            triggerSource: source,
            request: {
              userAttributes: {
                user: "attributes",
              },
              clientMetadata: {
                client: "metadata",
              },
              groupConfiguration,
            },
            response: { claimsOverrideDetails: {} },
            userName: "username",
          },
        });
      });

      it("adds the scopes and the version 2 response to a version 2 event", async () => {
        const { Payload } = await invoke("2");
        expect(Payload).toMatchObject({
          version: "2",
          request: {
            groupConfiguration,
            scopes: ["aws.cognito.signin.user.admin"],
          },
          response: { claimsAndScopeOverrideDetails: null },
        });
      });
    });

    it("sends a client credentials event without a user", async () => {
      mockLambdaClient.invoke.mockReturnValue(
        Promise.resolve({
          StatusCode: 200,
          Payload: encode('{ "response": {} }'),
        }) as any,
      );
      const lambda = new LambdaService(
        { PreTokenGeneration: "MyLambdaName" },
        mockLambdaClient,
      );

      await lambda.invoke(TestContext, "PreTokenGeneration", {
        clientId: "clientId",
        triggerSource: "TokenGeneration_ClientCredentials",
        username: "ClientCredentials",
        userPoolId: "userPoolId",
        userAttributes: {},
        clientMetadata: undefined,
        groupConfiguration: null,
        scopes: ["example.test/read"],
        version: "3",
      });

      expect(invokedWith(mockLambdaClient).Payload).toMatchObject({
        version: "3",
        triggerSource: "TokenGeneration_ClientCredentials",
        userName: "ClientCredentials",
        request: {
          userAttributes: {},
          groupConfiguration: null,
          scopes: ["example.test/read"],
        },
        response: { claimsAndScopeOverrideDetails: null },
      });
    });

    describe.each([
      "CustomMessage_SignUp",
      "CustomMessage_AdminCreateUser",
      "CustomMessage_ResendCode",
      "CustomMessage_ForgotPassword",
      "CustomMessage_UpdateUserAttribute",
      "CustomMessage_VerifyUserAttribute",
      "CustomMessage_Authentication",
    ] as const)("%s", (source) => {
      it("invokes the lambda function with the code parameter", async () => {
        const response = Promise.resolve({
          StatusCode: 200,
          Payload: encode('{ "some": "json" }'),
        });
        mockLambdaClient.invoke.mockReturnValue(response as any);
        const lambda = new LambdaService(
          {
            CustomMessage: "MyLambdaName",
          },
          mockLambdaClient,
        );

        await lambda.invoke(TestContext, "CustomMessage", {
          clientId: "clientId",
          clientMetadata: {
            client: "metadata",
          },
          codeParameter: "{####}",
          triggerSource: source,
          userAttributes: {},
          username: "username",
          usernameParameter: "{username}",
          userPoolId: "userPoolId",
        });

        expect(invokedWith(mockLambdaClient)).toEqual({
          FunctionName: "MyLambdaName",
          InvocationType: "RequestResponse",
          Payload: {
            version: "0",
            callerContext: {
              awsSdkVersion: "aws-sdk-unknown-unknown",
              clientId: "clientId",
            },
            region: "local",
            userPoolId: "userPoolId",
            triggerSource: source,
            userName: "username",
            request: {
              userAttributes: {},
              usernameParameter: "{username}",
              codeParameter: "{####}",
              clientMetadata: {
                client: "metadata",
              },
            },
            response: {
              smsMessage: "",
              emailMessage: "",
              emailSubject: "",
            },
          },
        });
      });
    });

    describe.each([
      "CustomEmailSender_SignUp",
      "CustomEmailSender_ResendCode",
      "CustomEmailSender_ForgotPassword",
      "CustomEmailSender_UpdateUserAttribute",
      "CustomEmailSender_VerifyUserAttribute",
      "CustomEmailSender_AdminCreateUser",
      "CustomEmailSender_Authentication",
    ] as const)("%s", (source) => {
      it("invokes the lambda function with the code parameter", async () => {
        const response = Promise.resolve({
          StatusCode: 200,
          Payload: encode('{ "some": "json" }'),
        });

        mockLambdaClient.invoke.mockReturnValue(response as any);

        const lambda = new LambdaService(
          {
            CustomEmailSender: "MyLambdaName",
          },
          mockLambdaClient,
        );

        await lambda.invoke(TestContext, "CustomEmailSender", {
          code: "code",
          clientId: "clientId",
          clientMetadata: {
            client: "metadata",
          },
          triggerSource: source,
          userAttributes: {},
          username: "username",
          userPoolId: "userPoolId",
        });

        expect(invokedWith(mockLambdaClient)).toEqual({
          FunctionName: "MyLambdaName",
          InvocationType: "RequestResponse",
          Payload: {
            version: "0",
            callerContext: {
              awsSdkVersion: "aws-sdk-unknown-unknown",
              clientId: "clientId",
            },
            region: "local",
            userPoolId: "userPoolId",
            triggerSource: source,
            userName: "username",
            request: {
              type: "customEmailSenderRequestV1",
              code: "code",
              userAttributes: {},
              clientMetadata: { client: "metadata" },
            },
            response: {},
          },
        });
      });
    });
  });
});
