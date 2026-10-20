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
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { NotAuthorizedError, UserNotFoundError } from "../errors";
import type { CognitoService, Messages, UserPoolService } from "../services";
import type { TokenVerifier } from "../services/tokenVerifier";
import { attributeValue } from "../services/userPoolService";
import { ForgotPassword, type ForgotPasswordTarget } from "./forgotPassword";

const currentDate = new Date();

describe("ForgotPassword target", () => {
  let mockCognito: MockedObject<CognitoService>;
  let mockTokenVerifier: MockedObject<TokenVerifier>;
  let forgotPassword: ForgotPasswordTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockMessages: MockedObject<Messages>;
  let mockOtp: Mock<() => string>;

  beforeEach(() => {
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
    ).rejects.toBeInstanceOf(UserNotFoundError);
  });

  it("sends a confirmation code to the user's email address", async () => {
    const user = TDB.user();

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
    const user = TDB.user();

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
});
