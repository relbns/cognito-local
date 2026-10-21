import {
  beforeEach,
  describe,
  expect,
  it,
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
import {
  ResendConfirmationCode,
  type ResendConfirmationCodeTarget,
} from "./resendConfirmationCode";

const currentDate = new Date();

describe("ResendConfirmationCode target", () => {
  let mockCognito: MockedObject<CognitoService>;
  let mockTokenVerifier: MockedObject<TokenVerifier>;
  let resendConfirmationCode: ResendConfirmationCodeTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockMessages: MockedObject<Messages>;
  let mockOtp: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService({
      Id: "test",
      AutoVerifiedAttributes: ["email"],
    });
    mockCognito = newMockCognitoService(mockUserPoolService);
    mockTokenVerifier = newMockTokenVerifier();
    mockMessages = newMockMessages();
    mockOtp = vi.fn().mockReturnValue("123456");

    resendConfirmationCode = ResendConfirmationCode({
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
      resendConfirmationCode(TestContext, {
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

  it("generates code, delivers message, saves on user", async () => {
    const user = TDB.user({
      UserStatus: "UNCONFIRMED",
      Attributes: [
        { Name: "email", Value: "user@example.com" },
        { Name: "sub", Value: "user-sub" },
      ],
    });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    const result = await resendConfirmationCode(TestContext, {
      ClientId: "test-client",
      Username: user.Username,
    });

    expect(result.CodeDeliveryDetails).toBeDefined();
    expect(mockMessages.deliver).toHaveBeenCalledWith(
      TestContext,
      "ResendCode",
      "test-client",
      "test",
      user,
      "123456",
      undefined,
      expect.objectContaining({
        AttributeName: "email",
        DeliveryMedium: "EMAIL",
      }),
    );
    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
      ...user,
      ConfirmationCode: "123456",
      UserLastModifiedDate: currentDate,
    });
  });

  it("throws if user not found", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      resendConfirmationCode(TestContext, {
        ClientId: "test-client",
        Username: "unknown",
      }),
    ).rejects.toBeInstanceOf(UserNotFoundError);
  });
});
