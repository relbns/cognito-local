import {
  beforeEach,
  describe,
  expect,
  it,
  type MockedObject,
  vi,
} from "vitest";
import { newMockLambda } from "../../__tests__/mockLambda";
import { TestContext } from "../../__tests__/testContext";
import type { CryptoService } from "../crypto";
import type { Lambda } from "../lambda";
import {
  CustomSMSSender,
  type CustomSMSSenderTrigger,
} from "./customSmsSender";

describe("CustomSMSSender trigger", () => {
  let mockLambda: MockedObject<Lambda>;
  let mockCrypto: MockedObject<CryptoService>;
  let customSmsSender: CustomSMSSenderTrigger;

  beforeEach(() => {
    mockLambda = newMockLambda();
    mockCrypto = {
      encrypt: vi.fn(),
    } as any as MockedObject<CryptoService>;

    customSmsSender = CustomSMSSender({
      lambda: mockLambda,
      crypto: mockCrypto,
    });
  });

  describe("when lambda invoke fails", () => {
    it("returns null", async () => {
      mockCrypto.encrypt.mockRejectedValue(new Error("Some Encrypt Failure"));

      const message = await customSmsSender(TestContext, {
        clientId: "clientId",
        clientMetadata: undefined,
        code: "decryptedCode",
        source: "CustomSMSSender_SignUp",
        userAttributes: [],
        username: "username",
        userPoolId: "userPoolId",
      });

      expect(message).toBeNull();
    });
  });

  describe("when lambda invoke succeeds", () => {
    beforeEach(() => {
      mockCrypto.encrypt.mockResolvedValueOnce("encryptedCode");
    });

    it("invokes the trigger with the encrypted code", async () => {
      await customSmsSender(TestContext, {
        clientId: "clientId",
        clientMetadata: { client: "metadata" },
        code: "decryptedCode",
        source: "CustomSMSSender_ForgotPassword",
        userAttributes: [{ Name: "user", Value: "hello" }],
        username: "+15555550100",
        userPoolId: "userPoolId",
      });

      expect(mockLambda.invoke).toHaveBeenCalledWith(
        TestContext,
        "CustomSMSSender",
        {
          code: "encryptedCode",
          clientId: "clientId",
          clientMetadata: { client: "metadata" },
          triggerSource: "CustomSMSSender_ForgotPassword",
          userAttributes: { user: "hello" },
          username: "+15555550100",
          userPoolId: "userPoolId",
        },
      );
    });
  });
});
