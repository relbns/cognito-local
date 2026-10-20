import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  AliasExistsError,
  CodeMismatchError,
  NotAuthorizedError,
} from "../errors";
import type { Triggers, UserPoolService } from "../services";
import { attribute, attributesAppend } from "../services/userPoolService";
import { ConfirmSignUp, type ConfirmSignUpTarget } from "./confirmSignUp";

const originalDate = new Date();

describe("ConfirmSignUp target", () => {
  let confirmSignUp: ConfirmSignUpTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockTriggers: MockedObject<Triggers>;
  let clock: ClockFake;

  beforeEach(() => {
    clock = new ClockFake(originalDate);

    mockUserPoolService = newMockUserPoolService();
    mockTriggers = newMockTriggers();
    confirmSignUp = ConfirmSignUp({
      cognito: newMockCognitoService(mockUserPoolService),
      clock,
      triggers: mockTriggers,
    });
  });

  it("throws if user doesn't exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      confirmSignUp(TestContext, {
        ClientId: "clientId",
        Username: "janice",
        ConfirmationCode: "123456",
        ForceAliasCreation: false,
      }),
    ).rejects.toBeInstanceOf(NotAuthorizedError);
  });

  it("throws if confirmation code doesn't match stored value", async () => {
    const user = TDB.user({
      ConfirmationCode: "456789",
      UserStatus: "UNCONFIRMED",
    });

    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      confirmSignUp(TestContext, {
        ClientId: "clientId",
        Username: user.Username,
        ConfirmationCode: "123456",
      }),
    ).rejects.toBeInstanceOf(CodeMismatchError);
  });

  describe("when code matches", () => {
    it("updates the user's confirmed status", async () => {
      const user = TDB.user({
        ConfirmationCode: "456789",
        UserStatus: "UNCONFIRMED",
      });

      mockUserPoolService.getUserByUsername.mockResolvedValue(user);

      // advance the time so we can see the last modified timestamp change
      const newNow = clock.advanceBy(5000);

      await confirmSignUp(TestContext, {
        ClientId: "clientId",
        Username: user.Username,
        ConfirmationCode: "456789",
      });

      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
        ...user,
        ConfirmationCode: undefined,
        UserLastModifiedDate: newNow,
        UserStatus: "CONFIRMED",
      });
    });

    describe("when PostConfirmation trigger configured", () => {
      it("invokes the trigger", async () => {
        mockTriggers.enabled.mockReturnValue(true);

        const user = TDB.user({
          ConfirmationCode: "456789",
          UserStatus: "UNCONFIRMED",
        });

        mockUserPoolService.getUserByUsername.mockResolvedValue(user);

        await confirmSignUp(TestContext, {
          ClientId: "clientId",
          ClientMetadata: {
            client: "metadata",
          },
          Username: "janice",
          ConfirmationCode: "456789",
          ForceAliasCreation: false,
        });

        expect(mockTriggers.postConfirmation).toHaveBeenCalledWith(
          TestContext,
          {
            clientId: "clientId",
            clientMetadata: {
              client: "metadata",
            },
            source: "PostConfirmation_ConfirmSignUp",
            userAttributes: attributesAppend(
              user.Attributes,
              attribute("cognito:user_status", "CONFIRMED"),
            ),
            userPoolId: "test",
            username: user.Username,
          },
        );
      });
    });

    describe("when PostConfirmation trigger not configured", () => {
      it("doesn't invoke the trigger", async () => {
        mockTriggers.enabled.mockReturnValue(false);

        const user = TDB.user({
          ConfirmationCode: "456789",
          UserStatus: "UNCONFIRMED",
        });

        mockUserPoolService.getUserByUsername.mockResolvedValue(user);

        await confirmSignUp(TestContext, {
          ClientId: "clientId",
          Username: user.Username,
          ConfirmationCode: "456789",
        });

        expect(mockTriggers.postConfirmation).not.toHaveBeenCalled();
      });
    });
  });

  describe("aliases", () => {
    const email = "jane@example.com";
    const other = TDB.user({
      Username: "other",
      Attributes: [
        attribute("email", email),
        attribute("email_verified", "true"),
      ],
    });
    const pending = TDB.user({
      Username: "jane",
      ConfirmationCode: "456789",
      UserStatus: "UNCONFIRMED",
      Attributes: [attribute("email", email)],
    });

    beforeEach(() => {
      mockUserPoolService.options.AliasAttributes = ["email"];
      mockUserPoolService.options.AutoVerifiedAttributes = ["email"];
      mockUserPoolService.getUserByUsername.mockImplementation(async (_, u) =>
        u === other.Username ? other : pending,
      );
      mockUserPoolService.listUsers.mockResolvedValue([other, pending]);
    });

    it("verifies the attribute the confirmation code was sent to", async () => {
      mockUserPoolService.listUsers.mockResolvedValue([pending]);

      await confirmSignUp(TestContext, {
        ClientId: "clientId",
        Username: pending.Username,
        ConfirmationCode: "456789",
      });

      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
        TestContext,
        expect.objectContaining({
          Attributes: attributesAppend(
            pending.Attributes,
            attribute("email_verified", "true"),
          ),
          UserStatus: "CONFIRMED",
        }),
      );
    });

    it("throws AliasExistsException when another user has the email verified", async () => {
      await expect(
        confirmSignUp(TestContext, {
          ClientId: "clientId",
          Username: pending.Username,
          ConfirmationCode: "456789",
        }),
      ).rejects.toEqual(new AliasExistsError("email"));
      expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
    });

    it("moves the alias with ForceAliasCreation and marks it unverified on the other user", async () => {
      await confirmSignUp(TestContext, {
        ClientId: "clientId",
        Username: pending.Username,
        ConfirmationCode: "456789",
        ForceAliasCreation: true,
      });

      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
        ...other,
        Attributes: attributesAppend(
          other.Attributes,
          attribute("email_verified", "false"),
        ),
        UserLastModifiedDate: clock.get(),
      });
      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
        TestContext,
        expect.objectContaining({
          Username: pending.Username,
          UserStatus: "CONFIRMED",
        }),
      );
    });

    it("confirms when the other user's email is not verified", async () => {
      const unverifiedOther = TDB.user({
        Username: "other",
        Attributes: [attribute("email", email)],
      });
      mockUserPoolService.listUsers.mockResolvedValue([
        unverifiedOther,
        pending,
      ]);

      await confirmSignUp(TestContext, {
        ClientId: "clientId",
        Username: pending.Username,
        ConfirmationCode: "456789",
      });

      expect(mockUserPoolService.saveUser).toHaveBeenCalledTimes(1);
    });
  });
});
