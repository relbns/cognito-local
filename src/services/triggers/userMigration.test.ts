import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../../__tests__/mockCognitoService";
import { newMockLambda } from "../../__tests__/mockLambda";
import { newMockUserPoolService } from "../../__tests__/mockUserPoolService";
import { UUID } from "../../__tests__/patterns";
import { TestContext } from "../../__tests__/testContext";
import * as TDB from "../../__tests__/testDataBuilder";
import {
  AliasExistsError,
  NotAuthorizedError,
  UserLambdaValidationError,
  UsernameExistsError,
} from "../../errors";
import { DateClock } from "../clock";
import type { Lambda } from "../lambda";
import type { UserPoolService } from "../userPoolService";
import { UserMigration, type UserMigrationTrigger } from "./userMigration";

describe("UserMigration trigger", () => {
  let mockLambda: MockedObject<Lambda>;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let userMigration: UserMigrationTrigger;

  beforeEach(() => {
    mockLambda = newMockLambda();
    mockUserPoolService = newMockUserPoolService();
    userMigration = UserMigration({
      clock: new DateClock(),
      cognitoClient: newMockCognitoService(mockUserPoolService),
      lambda: mockLambda,
    });
  });

  describe("when lambda invoke fails", () => {
    it("throws unauthorized error", async () => {
      mockLambda.invoke.mockRejectedValue(new Error("Something bad happened"));

      await expect(
        userMigration(TestContext, {
          clientId: "clientId",
          clientMetadata: undefined,
          password: "password",
          userAttributes: [],
          username: "username",
          userPoolId: "userPoolId",
          validationData: undefined,
        }),
      ).rejects.toBeInstanceOf(NotAuthorizedError);
    });
  });

  describe("when lambda invoke succeeds", () => {
    const migrate = (username = "jane") =>
      userMigration(TestContext, {
        clientMetadata: undefined,
        userPoolId: "userPoolId",
        clientId: "clientId",
        username,
        password: "password",
        userAttributes: [],
        validationData: { validation: "data" },
      });

    it("invokes the lambda with the sign-in request", async () => {
      mockLambda.invoke.mockResolvedValue({ userAttributes: {} });

      await userMigration(TestContext, {
        clientMetadata: { client: "metadata" },
        userPoolId: "userPoolId",
        clientId: "clientId",
        username: "jane@example.test",
        password: "password",
        userAttributes: [],
        validationData: { validation: "data" },
      });

      expect(mockLambda.invoke).toHaveBeenCalledWith(
        TestContext,
        "UserMigration",
        {
          clientId: "clientId",
          clientMetadata: { client: "metadata" },
          password: "password",
          triggerSource: "UserMigration_Authentication",
          userAttributes: {},
          userPoolId: "userPoolId",
          username: "jane@example.test",
          validationData: { validation: "data" },
        },
      );
    });

    it("keeps the sign-in username, generates a sub and stores the returned attributes", async () => {
      mockLambda.invoke.mockResolvedValue({
        userAttributes: { email: "jane@example.test", email_verified: "true" },
        finalUserStatus: "CONFIRMED",
      });

      const user = await migrate("jane");

      expect(user.Username).toEqual("jane");
      expect(user.Password).toEqual("password");
      expect(user.UserStatus).toEqual("CONFIRMED");
      expect(user.Attributes).toEqual([
        { Name: "email", Value: "jane@example.test" },
        { Name: "email_verified", Value: "true" },
        { Name: "sub", Value: expect.stringMatching(UUID) },
      ]);
      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
        TestContext,
        user,
      );
    });

    it("ignores a sub returned by the lambda", async () => {
      mockLambda.invoke.mockResolvedValue({
        userAttributes: { sub: "not-a-uuid" },
      });

      const user = await migrate();

      expect(user.Attributes).toEqual([
        { Name: "sub", Value: expect.stringMatching(UUID) },
      ]);
    });

    it("uses the username returned by the lambda and does not store it as an attribute", async () => {
      mockLambda.invoke.mockResolvedValue({
        userAttributes: { email: "jane@example.test", username: "thisuser" },
      });

      const user = await migrate("jane@example.test");

      expect(user.Username).toEqual("thisuser");
      expect(user.Attributes.map((a) => a.Name)).toEqual(["email", "sub"]);
    });

    it("uses the sub as the username when the pool signs in with email", async () => {
      mockUserPoolService.options.UsernameAttributes = ["email"];
      mockLambda.invoke.mockResolvedValue({ userAttributes: {} });

      const user = await migrate("jane@example.test");

      expect(user.Username).toEqual(expect.stringMatching(UUID));
      expect(user.Attributes).toContainEqual({
        Name: "sub",
        Value: user.Username,
      });
      expect(user.Attributes).toContainEqual({
        Name: "email",
        Value: "jane@example.test",
      });
    });

    it("uses the sub as the username when the pool signs in with a phone number", async () => {
      mockUserPoolService.options.UsernameAttributes = ["phone_number"];
      mockLambda.invoke.mockResolvedValue({ userAttributes: {} });

      const user = await migrate("+15555550100");

      expect(user.Username).toEqual(expect.stringMatching(UUID));
      expect(user.Attributes).toContainEqual({
        Name: "phone_number",
        Value: "+15555550100",
      });
    });

    it("defaults the status to RESET_REQUIRED when finalUserStatus is not CONFIRMED", async () => {
      mockLambda.invoke.mockResolvedValue({ userAttributes: {} });

      const user = await migrate();

      expect(user.UserStatus).toEqual("RESET_REQUIRED");
    });

    it("sets user to RESET_REQUIRED if finalUserStatus is RESET_REQUIRED in response", async () => {
      mockLambda.invoke.mockResolvedValue({
        userAttributes: {},
        finalUserStatus: "RESET_REQUIRED",
      });

      const user = await migrate();

      expect(user.UserStatus).toEqual("RESET_REQUIRED");
    });

    it("enables SMS MFA when enableSMSMFA is set", async () => {
      mockLambda.invoke.mockResolvedValue({
        userAttributes: { phone_number: "+15555550100" },
        enableSMSMFA: true,
      });

      const user = await migrate();

      expect(user.UserMFASettingList).toEqual(["SMS_MFA"]);
      expect(user.PreferredMfaSetting).toEqual("SMS_MFA");
    });

    it("fails when enableSMSMFA is set without a phone number", async () => {
      mockLambda.invoke.mockResolvedValue({
        userAttributes: {},
        enableSMSMFA: true,
      });

      await expect(migrate()).rejects.toBeInstanceOf(UserLambdaValidationError);
      expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
    });

    it("fails when the returned username belongs to another user", async () => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(
        TDB.user({ Username: "taken" }),
      );
      mockLambda.invoke.mockResolvedValue({
        userAttributes: { username: "taken" },
      });

      await expect(migrate()).rejects.toBeInstanceOf(UsernameExistsError);
      expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
    });

    describe("when another user has the returned email as an alias", () => {
      beforeEach(() => {
        mockUserPoolService.options.AliasAttributes = ["email"];
        mockUserPoolService.listUsers.mockResolvedValue([
          TDB.user({
            Username: "other",
            Attributes: [
              { Name: "email", Value: "jane@example.test" },
              { Name: "email_verified", Value: "true" },
            ],
          }),
        ]);
      });

      it("throws AliasExistsException without forceAliasCreation", async () => {
        mockLambda.invoke.mockResolvedValue({
          userAttributes: {
            email: "jane@example.test",
            email_verified: "true",
          },
        });

        await expect(migrate()).rejects.toBeInstanceOf(AliasExistsError);
        expect(mockUserPoolService.saveUser).not.toHaveBeenCalled();
      });

      it("moves the alias with forceAliasCreation", async () => {
        mockLambda.invoke.mockResolvedValue({
          userAttributes: {
            email: "jane@example.test",
            email_verified: "true",
          },
          forceAliasCreation: true,
        });

        const user = await migrate();

        expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
          TestContext,
          expect.objectContaining({
            Username: "other",
            Attributes: expect.arrayContaining([
              { Name: "email_verified", Value: "false" },
            ]),
          }),
        );
        expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
          TestContext,
          user,
        );
      });
    });
  });
});
