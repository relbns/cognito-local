import {
  beforeEach,
  describe,
  expect,
  it,
  type Mock,
  type MockedObject,
  vi,
} from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockMessages } from "../__tests__/mockMessages";
import { newMockTokenVerifier } from "../__tests__/mockTokenVerifier";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  InvalidParameterError,
  NotAuthorizedError,
  UserNotFoundError,
} from "../errors";
import type {
  CognitoService,
  Messages,
  Triggers,
  UserPoolService,
} from "../services";
import type { TokenVerifier } from "../services/tokenVerifier";
import { attributeValue, type UserPool } from "../services/userPoolService";
import { ForgotPassword, type ForgotPasswordTarget } from "./forgotPassword";

const currentDate = new Date();

const verifiedUser = (partial: Parameters<typeof TDB.user>[0] = {}) =>
  TDB.user({
    Attributes: [
      { Name: "sub", Value: "user-sub" },
      { Name: "email", Value: "user@example.test" },
      { Name: "email_verified", Value: "true" },
    ],
    ...partial,
  });

describe("ForgotPassword target", () => {
  let mockCognito: MockedObject<CognitoService>;
  let mockTokenVerifier: MockedObject<TokenVerifier>;
  let forgotPassword: ForgotPasswordTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockMessages: MockedObject<Messages>;
  let mockOtp: Mock<() => string>;
  let mockTriggers: MockedObject<Triggers>;

  beforeEach(() => {
    mockTriggers = newMockTriggers();
    mockTriggers.enabled.mockReturnValue(false);
    mockUserPoolService = newMockUserPoolService();
    mockCognito = newMockCognitoService(mockUserPoolService);
    mockTokenVerifier = newMockTokenVerifier();
    mockMessages = newMockMessages();
    mockOtp = vi.fn().mockReturnValue("123456");
    forgotPassword = ForgotPassword({
      cognito: mockCognito,
      tokenVerifier: mockTokenVerifier,
      clock: new ClockFake(currentDate),
      messages: mockMessages,
      otp: mockOtp,
      triggers: mockTriggers,
    });
  });

  it("checks SecretHash against the username", async () => {
    const client = TDB.appClient({ ClientSecret: "secret" });
    mockCognito.getAppClient.mockResolvedValue(client);
    mockTokenVerifier.verifySecretHash.mockImplementation(() => {
      throw new NotAuthorizedError("Unable to verify secret hash");
    });

    await expect(
      forgotPassword(TestContext, {
        ClientId: client.ClientId,
        Username: "u",
        SecretHash: "bad",
      }),
    ).rejects.toEqual(new NotAuthorizedError("Unable to verify secret hash"));
    expect(mockTokenVerifier.verifySecretHash).toHaveBeenCalledWith(
      client,
      ["u"],
      "bad",
    );
  });

  it("throws if user doesn't exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      forgotPassword(TestContext, {
        ClientId: "clientId",
        Username: "0000-0000",
      }),
    ).rejects.toEqual(
      new UserNotFoundError("Username/client id combination not found."),
    );
  });

  describe("UserMigration", () => {
    beforeEach(() => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(null);
      mockTriggers.enabled.mockImplementation(
        (name) => name === "UserMigration",
      );
    });

    it("migrates an unknown user and sends the code to the migrated user", async () => {
      const migrated = verifiedUser({ UserStatus: "RESET_REQUIRED" });
      mockTriggers.userMigration.mockResolvedValue(migrated);

      const result = await forgotPassword(TestContext, {
        ClientId: "clientId",
        Username: "legacy@example.test",
        ClientMetadata: { client: "metadata" },
      });

      expect(mockTriggers.userMigration).toHaveBeenCalledWith(TestContext, {
        clientId: "clientId",
        clientMetadata: { client: "metadata" },
        password: undefined,
        source: "UserMigration_ForgotPassword",
        userAttributes: [],
        username: "legacy@example.test",
        userPoolId: "test",
        validationData: undefined,
      });
      expect(mockMessages.deliver).toHaveBeenCalledWith(
        TestContext,
        "ForgotPassword",
        "clientId",
        "test",
        migrated,
        "123456",
        { client: "metadata" },
        expect.objectContaining({ DeliveryMedium: "EMAIL" }),
      );
      expect(result.CodeDeliveryDetails?.Destination).toBe(
        attributeValue("email", migrated.Attributes),
      );
    });

    it("answers user not found when the trigger rejects the user", async () => {
      mockTriggers.userMigration.mockRejectedValue(new NotAuthorizedError());

      await expect(
        forgotPassword(TestContext, {
          ClientId: "clientId",
          Username: "nobody@example.test",
        }),
      ).rejects.toBeInstanceOf(UserNotFoundError);
      expect(mockMessages.deliver).not.toHaveBeenCalled();
    });
  });

  it("sends a confirmation code to the user's email address", async () => {
    const user = verifiedUser();

    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    const result = await forgotPassword(TestContext, {
      ClientId: "clientId",
      Username: user.Username,
      ClientMetadata: { client: "metadata" },
    });

    expect(mockMessages.deliver).toHaveBeenCalledWith(
      TestContext,
      "ForgotPassword",
      "clientId",
      "test",
      user,
      "123456",
      { client: "metadata" },
      {
        AttributeName: "email",
        DeliveryMedium: "EMAIL",
        Destination: attributeValue("email", user.Attributes),
      },
    );

    expect(result).toEqual({
      CodeDeliveryDetails: {
        AttributeName: "email",
        DeliveryMedium: "EMAIL",
        Destination: attributeValue("email", user.Attributes),
      },
    });
  });

  it("saves the confirmation code on the user for comparison when confirming", async () => {
    const user = verifiedUser();

    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await forgotPassword(TestContext, {
      ClientId: "clientId",
      Username: user.Username,
    });

    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
      ...user,
      UserLastModifiedDate: currentDate,
      ConfirmationCode: "123456",
    });
  });

  describe("delivery", () => {
    const phoneAndEmail = (verified: { email?: boolean; phone?: boolean }) =>
      TDB.user({
        Attributes: [
          { Name: "sub", Value: "user-sub" },
          { Name: "email", Value: "user@example.test" },
          { Name: "email_verified", Value: String(!!verified.email) },
          { Name: "phone_number", Value: "+15555550100" },
          { Name: "phone_number_verified", Value: String(!!verified.phone) },
        ],
      });
    const sms = {
      AttributeName: "phone_number",
      DeliveryMedium: "SMS",
      Destination: "+15555550100",
    };
    const email = {
      AttributeName: "email",
      DeliveryMedium: "EMAIL",
      Destination: "user@example.test",
    };
    const send = async (
      user: ReturnType<typeof TDB.user>,
      AccountRecoverySetting?: UserPool["AccountRecoverySetting"],
    ) => {
      mockUserPoolService.options.AccountRecoverySetting =
        AccountRecoverySetting;
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      return forgotPassword(TestContext, {
        ClientId: "clientId",
        Username: user.Username,
      });
    };

    it("prefers a verified phone number when the pool has no AccountRecoverySetting", async () => {
      const result = await send(phoneAndEmail({ email: true, phone: true }));
      expect(result.CodeDeliveryDetails).toEqual(sms);
      expect(mockMessages.deliver).toHaveBeenCalledWith(
        TestContext,
        "ForgotPassword",
        "clientId",
        "test",
        expect.anything(),
        "123456",
        undefined,
        sms,
      );
    });

    it("follows the AccountRecoverySetting priorities", async () => {
      const emailFirst = {
        RecoveryMechanisms: [
          { Name: "verified_phone_number" as const, Priority: 2 },
          { Name: "verified_email" as const, Priority: 1 },
        ],
      };
      expect(
        (await send(phoneAndEmail({ email: true, phone: true }), emailFirst))
          .CodeDeliveryDetails,
      ).toEqual(email);
      expect(
        (await send(phoneAndEmail({ phone: true }), emailFirst))
          .CodeDeliveryDetails,
      ).toEqual(sms);
    });

    it("refuses a user with no verified email or phone number", async () => {
      await expect(send(phoneAndEmail({}))).rejects.toEqual(
        new InvalidParameterError(
          "Cannot reset password for the user as there is no registered/verified email or phone_number",
        ),
      );
      await expect(
        send(phoneAndEmail({ email: true, phone: true }), {
          RecoveryMechanisms: [{ Name: "admin_only", Priority: 1 }],
        }),
      ).rejects.toBeInstanceOf(InvalidParameterError);
      expect(mockMessages.deliver).not.toHaveBeenCalled();
    });

    it("simulates delivery for a user with no verified attribute when existence errors are prevented", async () => {
      mockCognito.getAppClient.mockResolvedValue(
        TDB.appClient({ PreventUserExistenceErrors: "ENABLED" }),
      );
      const result = await send(phoneAndEmail({}));
      expect(result.CodeDeliveryDetails?.DeliveryMedium).toBe("SMS");
      expect(mockMessages.deliver).not.toHaveBeenCalled();
    });
  });
});
