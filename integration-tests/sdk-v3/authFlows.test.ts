import {
  AdminCreateUserCommand,
  AdminForgetDeviceCommand,
  AdminGetDeviceCommand,
  AdminInitiateAuthCommand,
  AdminListDevicesCommand,
  AdminSetUserPasswordCommand,
  AssociateSoftwareTokenCommand,
  CognitoIdentityProviderClient,
  ConfirmDeviceCommand,
  CreateUserPoolClientCommand,
  CreateUserPoolCommand,
  type CreateUserPoolCommandInput,
  GetDeviceCommand,
  GetUserCommand,
  InitiateAuthCommand,
  InvalidParameterException,
  ListDevicesCommand,
  NotAuthorizedException,
  ResourceNotFoundException,
  RespondToAuthChallengeCommand,
  SetUserPoolMfaConfigCommand,
  UpdateDeviceStatusCommand,
  VerifySoftwareTokenCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import {
  AuthenticationDetails,
  CognitoUser,
  CognitoUserPool,
  type CognitoUserSession,
} from "amazon-cognito-identity-js";
import { describe, expect, it } from "vitest";
import {
  deviceSecret,
  deviceSrpClient,
  srpClient,
} from "../../src/__tests__/srpClient";
import { generate as totpCode } from "../../src/services/totp";
import { withCognitoSdk } from "../aws-sdk/setup";

const PASSWORD = "Example-Passw0rd!";
const EMAIL = "flow-user@example.test";
const credentials = { accessKeyId: "local", secretAccessKey: "local" };

const newClient = (endpoint: string) =>
  new CognitoIdentityProviderClient({
    endpoint,
    region: "local",
    credentials,
    maxAttempts: 1,
  });

const setUp = async (
  cognito: CognitoIdentityProviderClient,
  pool: Partial<CreateUserPoolCommandInput> = {},
  explicitAuthFlows = [
    "ALLOW_USER_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ] as const,
) => {
  const created = await cognito.send(
    new CreateUserPoolCommand({ PoolName: "flows", ...pool }),
  );
  const userPoolId = created.UserPool?.Id as string;
  const appClient = await cognito.send(
    new CreateUserPoolClientCommand({
      UserPoolId: userPoolId,
      ClientName: "flows",
      ExplicitAuthFlows: [...explicitAuthFlows],
    }),
  );
  await cognito.send(
    new AdminCreateUserCommand({
      UserPoolId: userPoolId,
      Username: "flow-user",
      MessageAction: "SUPPRESS",
      UserAttributes: [{ Name: "email", Value: EMAIL }],
    }),
  );
  await cognito.send(
    new AdminSetUserPasswordCommand({
      UserPoolId: userPoolId,
      Username: "flow-user",
      Password: PASSWORD,
      Permanent: true,
    }),
  );
  return {
    userPoolId,
    clientId: appClient.UserPoolClient?.ClientId as string,
  };
};

describe(
  "authentication flows over AWS SDK v3",
  withCognitoSdk((_, { serverUrl, messageDelivery }) => {
    const lastCode = () =>
      messageDelivery().collectedMessages.at(-1)?.message.__code as string;

    describe("USER_AUTH", () => {
      const otpPool = {
        Policies: {
          SignInPolicy: {
            AllowedFirstAuthFactors: [
              "PASSWORD" as const,
              "EMAIL_OTP" as const,
            ],
          },
        },
      };

      it("lists the choices, sends an EMAIL_OTP code and signs in with it", async () => {
        const cognito = newClient(serverUrl());
        const { clientId } = await setUp(cognito, otpPool);

        const select = await cognito.send(
          new InitiateAuthCommand({
            AuthFlow: "USER_AUTH",
            ClientId: clientId,
            AuthParameters: { USERNAME: "flow-user" },
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
            ChallengeResponses: { USERNAME: "flow-user", ANSWER: "EMAIL_OTP" },
          }),
        );
        expect(otp.ChallengeName).toEqual("EMAIL_OTP");
        expect(otp.ChallengeParameters).toEqual({
          CODE_DELIVERY_DELIVERY_MEDIUM: "EMAIL",
          CODE_DELIVERY_DESTINATION: EMAIL,
        });
        expect(
          messageDelivery().collectedMessages.at(-1)?.deliveryDetails,
        ).toEqual({
          DeliveryMedium: "EMAIL",
          AttributeName: "email",
          Destination: EMAIL,
        });

        const signedIn = await cognito.send(
          new RespondToAuthChallengeCommand({
            ClientId: clientId,
            ChallengeName: "EMAIL_OTP",
            Session: otp.Session,
            ChallengeResponses: {
              USERNAME: "flow-user",
              EMAIL_OTP_CODE: lastCode(),
            },
          }),
        );
        const user = await cognito.send(
          new GetUserCommand({
            AccessToken: signedIn.AuthenticationResult?.AccessToken,
          }),
        );
        expect(user.UserAttributes).toContainEqual({
          Name: "email_verified",
          Value: "true",
        });
      });

      it("goes straight to PASSWORD_VERIFIER for a preferred PASSWORD_SRP", async () => {
        const cognito = newClient(serverUrl());
        const { userPoolId, clientId } = await setUp(cognito);
        const srp = srpClient(userPoolId);

        const verifier = await cognito.send(
          new InitiateAuthCommand({
            AuthFlow: "USER_AUTH",
            ClientId: clientId,
            AuthParameters: {
              USERNAME: "flow-user",
              PREFERRED_CHALLENGE: "PASSWORD_SRP",
              SRP_A: srp.srpA,
            },
          }),
        );
        expect(verifier.ChallengeName).toEqual("PASSWORD_VERIFIER");

        const signedIn = await cognito.send(
          new RespondToAuthChallengeCommand({
            ClientId: clientId,
            ChallengeName: "PASSWORD_VERIFIER",
            Session: verifier.Session,
            ChallengeResponses: srp.respond(
              verifier.ChallengeParameters ?? {},
              PASSWORD,
            ),
          }),
        );
        expect(signedIn.AuthenticationResult?.AccessToken).toBeDefined();
      });

      it("signs in with AdminInitiateAuth and a preferred PASSWORD", async () => {
        const cognito = newClient(serverUrl());
        const { userPoolId, clientId } = await setUp(cognito);

        const signedIn = await cognito.send(
          new AdminInitiateAuthCommand({
            AuthFlow: "USER_AUTH",
            UserPoolId: userPoolId,
            ClientId: clientId,
            AuthParameters: {
              USERNAME: "flow-user",
              PREFERRED_CHALLENGE: "PASSWORD",
              PASSWORD,
            },
          }),
        );
        expect(signedIn.AuthenticationResult?.IdToken).toBeDefined();
      });

      it("refuses USER_AUTH on a client without ALLOW_USER_AUTH", async () => {
        const cognito = newClient(serverUrl());
        const { clientId } = await setUp(cognito, {}, [
          "ALLOW_USER_SRP_AUTH",
          "ALLOW_REFRESH_TOKEN_AUTH",
        ] as never);

        const error = await cognito
          .send(
            new InitiateAuthCommand({
              AuthFlow: "USER_AUTH",
              ClientId: clientId,
              AuthParameters: { USERNAME: "flow-user" },
            }),
          )
          .catch((e) => e);
        expect(error).toBeInstanceOf(InvalidParameterException);
        expect(error.message).toEqual(
          "USER_AUTH flow not enabled for this client",
        );
      });
    });

    describe("MFA_SETUP", () => {
      it("registers TOTP with the challenge Session and signs in, then asks for TOTP next time", async () => {
        const cognito = newClient(serverUrl());
        const { userPoolId, clientId } = await setUp(cognito);
        await cognito.send(
          new SetUserPoolMfaConfigCommand({
            UserPoolId: userPoolId,
            MfaConfiguration: "ON",
            SoftwareTokenMfaConfiguration: { Enabled: true },
          }),
        );
        const signIn = () =>
          cognito.send(
            new InitiateAuthCommand({
              AuthFlow: "USER_PASSWORD_AUTH",
              ClientId: clientId,
              AuthParameters: { USERNAME: "flow-user", PASSWORD },
            }),
          );

        const setup = await signIn();
        expect(setup.ChallengeName).toEqual("MFA_SETUP");
        expect(setup.ChallengeParameters?.MFAS_CAN_SETUP).toEqual(
          '["SOFTWARE_TOKEN_MFA"]',
        );

        const early = await cognito
          .send(
            new RespondToAuthChallengeCommand({
              ClientId: clientId,
              ChallengeName: "MFA_SETUP",
              Session: setup.Session,
              ChallengeResponses: { USERNAME: "flow-user" },
            }),
          )
          .catch((e) => e);
        expect(early).toBeInstanceOf(NotAuthorizedException);

        const retry = await signIn();
        const associated = await cognito.send(
          new AssociateSoftwareTokenCommand({ Session: retry.Session }),
        );
        const secret = associated.SecretCode as string;
        const verified = await cognito.send(
          new VerifySoftwareTokenCommand({
            Session: associated.Session,
            UserCode: totpCode(secret),
          }),
        );
        expect(verified.Status).toEqual("SUCCESS");

        const signedIn = await cognito.send(
          new RespondToAuthChallengeCommand({
            ClientId: clientId,
            ChallengeName: "MFA_SETUP",
            Session: verified.Session,
            ChallengeResponses: { USERNAME: "flow-user" },
          }),
        );
        expect(signedIn.AuthenticationResult?.AccessToken).toBeDefined();

        const next = await signIn();
        expect(next.ChallengeName).toEqual("SOFTWARE_TOKEN_MFA");
        const again = await cognito.send(
          new RespondToAuthChallengeCommand({
            ClientId: clientId,
            ChallengeName: "SOFTWARE_TOKEN_MFA",
            Session: next.Session,
            ChallengeResponses: {
              USERNAME: "flow-user",
              SOFTWARE_TOKEN_MFA_CODE: totpCode(secret),
            },
          }),
        );
        expect(again.AuthenticationResult?.AccessToken).toBeDefined();
      });
    });

    describe("devices", () => {
      const devicePool = {
        DeviceConfiguration: {
          ChallengeRequiredOnNewDevice: true,
          DeviceOnlyRememberedOnUserPrompt: true,
        },
      };

      it("issues, confirms, lists, updates and forgets a device", async () => {
        const cognito = newClient(serverUrl());
        const { userPoolId, clientId } = await setUp(cognito, devicePool);

        const signedIn = await cognito.send(
          new InitiateAuthCommand({
            AuthFlow: "USER_PASSWORD_AUTH",
            ClientId: clientId,
            AuthParameters: { USERNAME: "flow-user", PASSWORD },
          }),
        );
        const metadata = signedIn.AuthenticationResult?.NewDeviceMetadata;
        expect(metadata?.DeviceKey).toMatch(/^local_[0-9a-f-]{36}$/);
        const AccessToken = signedIn.AuthenticationResult?.AccessToken;
        const DeviceKey = metadata?.DeviceKey as string;

        const confirmed = await cognito.send(
          new ConfirmDeviceCommand({
            AccessToken,
            DeviceKey,
            DeviceName: "Test laptop",
            DeviceSecretVerifierConfig: deviceSecret(
              metadata?.DeviceGroupKey as string,
              DeviceKey,
            ).verifierConfig,
          }),
        );
        expect(confirmed.UserConfirmationNecessary).toBe(true);

        const listed = await cognito.send(
          new ListDevicesCommand({ AccessToken }),
        );
        expect(listed.Devices).toEqual([
          expect.objectContaining({
            DeviceKey,
            DeviceAttributes: [
              { Name: "device_status", Value: "valid" },
              { Name: "device_name", Value: "Test laptop" },
              { Name: "dev:device_remembered_status", Value: "not_remembered" },
            ],
          }),
        ]);

        await cognito.send(
          new UpdateDeviceStatusCommand({
            AccessToken,
            DeviceKey,
            DeviceRememberedStatus: "remembered",
          }),
        );
        const device = await cognito.send(
          new AdminGetDeviceCommand({
            UserPoolId: userPoolId,
            Username: "flow-user",
            DeviceKey,
          }),
        );
        expect(device.Device?.DeviceAttributes).toContainEqual({
          Name: "dev:device_remembered_status",
          Value: "remembered",
        });

        await cognito.send(
          new AdminForgetDeviceCommand({
            UserPoolId: userPoolId,
            Username: "flow-user",
            DeviceKey,
          }),
        );
        const afterForget = await cognito.send(
          new AdminListDevicesCommand({
            UserPoolId: userPoolId,
            Username: "flow-user",
          }),
        );
        expect(afterForget.Devices).toEqual([]);
        await expect(
          cognito.send(new GetDeviceCommand({ AccessToken, DeviceKey })),
        ).rejects.toBeInstanceOf(ResourceNotFoundException);
      });

      it("replaces TOTP with DEVICE_SRP_AUTH on a remembered device", async () => {
        const cognito = newClient(serverUrl());
        const { userPoolId, clientId } = await setUp(cognito, {
          ...devicePool,
          MfaConfiguration: "ON",
        });
        await cognito.send(
          new SetUserPoolMfaConfigCommand({
            UserPoolId: userPoolId,
            MfaConfiguration: "ON",
            SoftwareTokenMfaConfiguration: { Enabled: true },
          }),
        );
        const setup = await cognito.send(
          new InitiateAuthCommand({
            AuthFlow: "USER_PASSWORD_AUTH",
            ClientId: clientId,
            AuthParameters: { USERNAME: "flow-user", PASSWORD },
          }),
        );
        const associated = await cognito.send(
          new AssociateSoftwareTokenCommand({ Session: setup.Session }),
        );
        const verified = await cognito.send(
          new VerifySoftwareTokenCommand({
            Session: associated.Session,
            UserCode: totpCode(associated.SecretCode as string),
          }),
        );
        const first = await cognito.send(
          new RespondToAuthChallengeCommand({
            ClientId: clientId,
            ChallengeName: "MFA_SETUP",
            Session: verified.Session,
            ChallengeResponses: { USERNAME: "flow-user" },
          }),
        );
        const metadata = first.AuthenticationResult?.NewDeviceMetadata;
        const DeviceKey = metadata?.DeviceKey as string;
        const DeviceGroupKey = metadata?.DeviceGroupKey as string;
        const secret = deviceSecret(DeviceGroupKey, DeviceKey);
        await cognito.send(
          new ConfirmDeviceCommand({
            AccessToken: first.AuthenticationResult?.AccessToken,
            DeviceKey,
            DeviceSecretVerifierConfig: secret.verifierConfig,
          }),
        );
        await cognito.send(
          new UpdateDeviceStatusCommand({
            AccessToken: first.AuthenticationResult?.AccessToken,
            DeviceKey,
            DeviceRememberedStatus: "remembered",
          }),
        );

        const deviceChallenge = await cognito.send(
          new InitiateAuthCommand({
            AuthFlow: "USER_PASSWORD_AUTH",
            ClientId: clientId,
            AuthParameters: {
              USERNAME: "flow-user",
              PASSWORD,
              DEVICE_KEY: DeviceKey,
            },
          }),
        );
        expect(deviceChallenge.ChallengeName).toEqual("DEVICE_SRP_AUTH");

        const device = deviceSrpClient(
          "flow-user",
          DeviceGroupKey,
          DeviceKey,
          secret.devicePassword,
        );
        const verifier = await cognito.send(
          new RespondToAuthChallengeCommand({
            ClientId: clientId,
            ChallengeName: "DEVICE_SRP_AUTH",
            Session: deviceChallenge.Session,
            ChallengeResponses: {
              USERNAME: "flow-user",
              DEVICE_KEY: DeviceKey,
              SRP_A: device.srpA,
            },
          }),
        );
        expect(verifier.ChallengeName).toEqual("DEVICE_PASSWORD_VERIFIER");

        const signedIn = await cognito.send(
          new RespondToAuthChallengeCommand({
            ClientId: clientId,
            ChallengeName: "DEVICE_PASSWORD_VERIFIER",
            Session: verifier.Session,
            ChallengeResponses: device.respond(
              verifier.ChallengeParameters ?? {},
            ),
          }),
        );
        expect(signedIn.AuthenticationResult?.AccessToken).toBeDefined();
        expect(
          signedIn.AuthenticationResult?.NewDeviceMetadata,
        ).toBeUndefined();

        const unknown = await cognito
          .send(
            new InitiateAuthCommand({
              AuthFlow: "USER_PASSWORD_AUTH",
              ClientId: clientId,
              AuthParameters: {
                USERNAME: "flow-user",
                PASSWORD,
                DEVICE_KEY: "local_00000000-0000-0000-0000-000000000000",
              },
            }),
          )
          .catch((e) => e);
        expect(unknown).toBeInstanceOf(ResourceNotFoundException);
        expect(unknown.message).toEqual("Device does not exist.");
      });
    });
  }),
);

type LibraryOutcome =
  | {
      kind: "success";
      session: CognitoUserSession;
      confirmationNecessary?: boolean;
    }
  | { kind: "mfaSetup" }
  | { kind: "totpRequired" };

const libraryCallbacks = (
  resolve: (outcome: LibraryOutcome) => void,
  reject: (error: unknown) => void,
) => ({
  onSuccess: (session: CognitoUserSession, confirmationNecessary?: boolean) =>
    resolve({ kind: "success", session, confirmationNecessary }),
  onFailure: reject,
  mfaSetup: () => resolve({ kind: "mfaSetup" }),
  totpRequired: () => resolve({ kind: "totpRequired" }),
});

describe(
  "MFA setup and remembered devices with amazon-cognito-identity-js",
  withCognitoSdk((_, { serverUrl }) => {
    it("sets up TOTP, remembers the device and then signs in with device SRP instead of TOTP", async () => {
      const cognito = newClient(serverUrl());
      const { userPoolId, clientId } = await setUp(cognito, {
        MfaConfiguration: "ON",
        DeviceConfiguration: {
          ChallengeRequiredOnNewDevice: true,
          DeviceOnlyRememberedOnUserPrompt: true,
        },
      });
      await cognito.send(
        new SetUserPoolMfaConfigCommand({
          UserPoolId: userPoolId,
          MfaConfiguration: "ON",
          SoftwareTokenMfaConfiguration: { Enabled: true },
        }),
      );
      const pool = new CognitoUserPool({
        UserPoolId: userPoolId,
        ClientId: clientId,
        endpoint: serverUrl(),
      });
      const user = new CognitoUser({ Username: "flow-user", Pool: pool });
      const details = new AuthenticationDetails({
        Username: "flow-user",
        Password: PASSWORD,
      });
      const authenticate = () =>
        new Promise<LibraryOutcome>((resolve, reject) =>
          user.authenticateUser(details, libraryCallbacks(resolve, reject)),
        );

      expect((await authenticate()).kind).toEqual("mfaSetup");
      const secret = await new Promise<string>((resolve, reject) =>
        user.associateSoftwareToken({
          associateSecretCode: resolve,
          onFailure: reject,
        }),
      );
      const afterSetup = await new Promise<CognitoUserSession>(
        (resolve, reject) =>
          user.verifySoftwareToken(totpCode(secret), "Authenticator", {
            onSuccess: resolve,
            onFailure: reject,
          }),
      );
      expect(afterSetup.isValid()).toBe(true);

      expect((await authenticate()).kind).toEqual("totpRequired");
      const afterTotp = await new Promise<LibraryOutcome>((resolve, reject) =>
        user.sendMFACode(
          totpCode(secret),
          libraryCallbacks(resolve, reject),
          "SOFTWARE_TOKEN_MFA",
        ),
      );
      expect(afterTotp).toMatchObject({
        kind: "success",
        confirmationNecessary: true,
      });
      await new Promise((resolve, reject) =>
        user.setDeviceStatusRemembered({
          onSuccess: resolve,
          onFailure: reject,
        }),
      );

      const devices = await cognito.send(
        new AdminListDevicesCommand({
          UserPoolId: userPoolId,
          Username: "flow-user",
        }),
      );
      expect(devices.Devices).toHaveLength(1);

      const remembered = await authenticate();
      expect(remembered.kind).toEqual("success");
      if (remembered.kind === "success") {
        expect(
          remembered.session.getIdToken().payload["cognito:username"],
        ).toBe("flow-user");
      }
      const afterDevice = await cognito.send(
        new AdminGetDeviceCommand({
          UserPoolId: userPoolId,
          Username: "flow-user",
          DeviceKey: devices.Devices?.[0].DeviceKey,
        }),
      );
      expect(
        afterDevice.Device?.DeviceLastAuthenticatedDate?.getTime(),
      ).toBeGreaterThanOrEqual(
        devices.Devices?.[0].DeviceLastAuthenticatedDate?.getTime() ?? 0,
      );
    });
  }),
);
