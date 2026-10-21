import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockMessageDelivery } from "../__tests__/mockMessageDelivery";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import type { MessageDelivery } from "./messageDelivery/messageDelivery";
import { MessagesService } from "./messages";
import type { Triggers } from "./triggers";

describe("messages service", () => {
  let mockTriggers: MockedObject<Triggers>;
  let mockMessageDelivery: MockedObject<MessageDelivery>;

  const user = TDB.user();
  const deliveryDetails = {
    AttributeName: "email",
    DeliveryMedium: "EMAIL",
    Destination: "example@example.com",
  } as const;

  beforeEach(() => {
    mockTriggers = newMockTriggers();
    mockMessageDelivery = newMockMessageDelivery();
  });

  describe.each([
    "AdminCreateUser",
    "Authentication",
    "ForgotPassword",
    "ResendCode",
    "SignUp",
    "UpdateUserAttribute",
    "VerifyUserAttribute",
  ] as const)("%s", (source) => {
    describe("CustomMessage lambda is configured", () => {
      describe("lambda returns a custom message", () => {
        it("delivers the customised message", async () => {
          mockTriggers.enabled.mockImplementation((name) => {
            return name === "CustomMessage";
          });
          mockTriggers.customMessage.mockResolvedValue({
            smsMessage: "sms",
            emailSubject: "email subject",
            emailMessage: "email",
          });

          const messages = new MessagesService(
            mockTriggers,
            mockMessageDelivery,
          );
          await messages.deliver(
            TestContext,
            source,
            "clientId",
            "userPoolId",
            user,
            "123456",
            {
              client: "metadata",
            },
            deliveryDetails,
          );

          expect(mockTriggers.customMessage).toHaveBeenCalledWith(TestContext, {
            clientId: "clientId",
            clientMetadata: {
              client: "metadata",
            },
            code: "123456",
            source: `CustomMessage_${source}`,
            userAttributes: user.Attributes,
            userPoolId: "userPoolId",
            username: user.Username,
          });

          expect(mockMessageDelivery.deliver).toHaveBeenCalledWith(
            TestContext,
            user,
            deliveryDetails,
            {
              __code: "123456",
              emailMessage: "email",
              emailSubject: "email subject",
              smsMessage: "sms",
            },
          );
        });
      });

      describe("lambda does not return a custom message", () => {
        it("delivers just the code", async () => {
          mockTriggers.enabled.mockImplementation((name) => {
            return name === "CustomMessage";
          });
          mockTriggers.customMessage.mockResolvedValue(null);

          const messages = new MessagesService(
            mockTriggers,
            mockMessageDelivery,
          );
          await messages.deliver(
            TestContext,
            source,
            "clientId",
            "userPoolId",
            user,
            "123456",
            {
              client: "metadata",
            },
            deliveryDetails,
          );

          expect(mockTriggers.customMessage).toHaveBeenCalledWith(TestContext, {
            clientId: "clientId",
            clientMetadata: {
              client: "metadata",
            },
            code: "123456",
            source: `CustomMessage_${source}`,
            userAttributes: user.Attributes,
            userPoolId: "userPoolId",
            username: user.Username,
          });

          expect(mockMessageDelivery.deliver).toHaveBeenCalledWith(
            TestContext,
            user,
            deliveryDetails,
            {
              __code: "123456",
            },
          );
        });
      });
    });

    describe("CustomMessage lambda is not configured", () => {
      it("delivers just the code", async () => {
        mockTriggers.enabled.mockReturnValue(false);

        const messages = new MessagesService(mockTriggers, mockMessageDelivery);
        await messages.deliver(
          TestContext,
          source,
          "clientId",
          "userPoolId",
          user,
          "123456",
          {
            client: "metadata",
          },
          deliveryDetails,
        );

        expect(mockTriggers.customMessage).not.toHaveBeenCalled();
        expect(mockMessageDelivery.deliver).toHaveBeenCalledWith(
          TestContext,
          user,
          deliveryDetails,
          {
            __code: "123456",
          },
        );
      });
    });
  });

  describe("custom senders", () => {
    const smsDelivery = {
      AttributeName: "phone_number",
      DeliveryMedium: "SMS",
      Destination: "+15555550100",
    } as const;

    const deliver = (
      source: "SignUp" | "Authentication",
      details: typeof smsDelivery | typeof deliveryDetails,
    ) =>
      new MessagesService(mockTriggers, mockMessageDelivery).deliver(
        TestContext,
        source,
        null,
        "userPoolId",
        user,
        "123456",
        { client: "metadata" },
        details,
      );

    it.each(["SignUp", "Authentication"] as const)(
      "hands a %s SMS to CustomSMSSender instead of delivering it",
      async (source) => {
        mockTriggers.enabled.mockImplementation(
          (name) => name === "CustomSMSSender",
        );

        await deliver(source, smsDelivery);

        expect(mockTriggers.customSmsSender).toHaveBeenCalledWith(TestContext, {
          clientId: "CLIENT_ID_NOT_APPLICABLE",
          clientMetadata: { client: "metadata" },
          code: "123456",
          source: `CustomSMSSender_${source}`,
          userAttributes: user.Attributes,
          username: user.Username,
          userPoolId: "userPoolId",
        });
        expect(mockMessageDelivery.deliver).not.toHaveBeenCalled();
      },
    );

    it("delivers an email normally when only CustomSMSSender is configured", async () => {
      mockTriggers.enabled.mockImplementation(
        (name) => name === "CustomSMSSender",
      );

      await deliver("SignUp", deliveryDetails);

      expect(mockTriggers.customSmsSender).not.toHaveBeenCalled();
      expect(mockMessageDelivery.deliver).toHaveBeenCalled();
    });

    it("delivers an SMS normally when only CustomEmailSender is configured", async () => {
      mockTriggers.enabled.mockImplementation(
        (name) => name === "CustomEmailSender",
      );

      await deliver("SignUp", smsDelivery);

      expect(mockTriggers.customEmailSender).not.toHaveBeenCalled();
      expect(mockMessageDelivery.deliver).toHaveBeenCalledWith(
        TestContext,
        user,
        smsDelivery,
        { __code: "123456" },
      );
    });

    it.each(["SignUp", "Authentication"] as const)(
      "hands a %s email to CustomEmailSender",
      async (source) => {
        mockTriggers.enabled.mockImplementation(
          (name) => name === "CustomEmailSender" || name === "CustomSMSSender",
        );

        await deliver(source, deliveryDetails);

        expect(mockTriggers.customEmailSender).toHaveBeenCalledWith(
          TestContext,
          expect.objectContaining({ source: `CustomEmailSender_${source}` }),
        );
        expect(mockTriggers.customSmsSender).not.toHaveBeenCalled();
        expect(mockMessageDelivery.deliver).not.toHaveBeenCalled();
      },
    );
  });
});
