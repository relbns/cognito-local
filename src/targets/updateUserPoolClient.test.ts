import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError, ResourceNotFoundError } from "../errors";
import type { CognitoService, UserPoolService } from "../services";
import {
  UpdateUserPoolClient,
  type UpdateUserPoolClientTarget,
} from "./updateUserPoolClient";

const originalDate = new Date();

describe("UpdateUserPoolClient target", () => {
  let updateUserPoolClient: UpdateUserPoolClientTarget;
  let mockCognitoService: MockedObject<CognitoService>;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let clock: ClockFake;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    mockCognitoService = newMockCognitoService(mockUserPoolService);
    clock = new ClockFake(originalDate);

    updateUserPoolClient = UpdateUserPoolClient({
      clock,
      cognito: mockCognitoService,
    });
  });

  it("updates a user pool client", async () => {
    const existingAppClient = TDB.appClient({
      UserPoolId: "test",
    });

    mockCognitoService.getAppClient.mockResolvedValue(existingAppClient);

    const newDate = new Date();
    clock.advanceTo(new Date());

    const result = await updateUserPoolClient(TestContext, {
      ClientId: existingAppClient.ClientId,
      UserPoolId: existingAppClient.UserPoolId,
      ClientName: "new client name",
      AccessTokenValidity: 5,
    });

    expect(mockCognitoService.getAppClient).toHaveBeenCalledWith(
      TestContext,
      existingAppClient.ClientId,
    );

    expect(mockUserPoolService.saveAppClient).toHaveBeenCalledWith(
      TestContext,
      {
        ...existingAppClient,
        AccessTokenValidity: 5,
        ClientName: "new client name",
        LastModifiedDate: newDate,
        TokenValidityUnits: {
          AccessToken: "hours",
          IdToken: "hours",
          RefreshToken: "days",
        },
      },
    );

    expect(result.UserPoolClient).toEqual({
      ...existingAppClient,
      AccessTokenValidity: 5,
      ClientName: "new client name",
      LastModifiedDate: newDate,
      TokenValidityUnits: {
        AccessToken: "hours",
        IdToken: "hours",
        RefreshToken: "days",
      },
    });
  });

  it("updates AuthSessionValidity and keeps it when omitted", async () => {
    const existingAppClient = TDB.appClient({
      UserPoolId: "test",
      AuthSessionValidity: 5,
    });
    mockCognitoService.getAppClient.mockResolvedValue(existingAppClient);

    const kept = await updateUserPoolClient(TestContext, {
      ClientId: existingAppClient.ClientId,
      UserPoolId: existingAppClient.UserPoolId,
    });
    expect(kept.UserPoolClient?.AuthSessionValidity).toEqual(5);

    const changed = await updateUserPoolClient(TestContext, {
      ClientId: existingAppClient.ClientId,
      UserPoolId: existingAppClient.UserPoolId,
      AuthSessionValidity: 12,
    });
    expect(changed.UserPoolClient?.AuthSessionValidity).toEqual(12);
  });

  it("updates RefreshTokenRotation and keeps it when omitted", async () => {
    const existingAppClient = TDB.appClient({ UserPoolId: "test" });
    mockCognitoService.getAppClient.mockResolvedValue(existingAppClient);

    const changed = await updateUserPoolClient(TestContext, {
      ClientId: existingAppClient.ClientId,
      UserPoolId: existingAppClient.UserPoolId,
      RefreshTokenRotation: { Feature: "ENABLED", RetryGracePeriodSeconds: 30 },
    });
    expect(changed.UserPoolClient?.RefreshTokenRotation).toEqual({
      Feature: "ENABLED",
      RetryGracePeriodSeconds: 30,
    });

    mockCognitoService.getAppClient.mockResolvedValue({
      ...existingAppClient,
      RefreshTokenRotation: { Feature: "ENABLED", RetryGracePeriodSeconds: 30 },
    });
    const kept = await updateUserPoolClient(TestContext, {
      ClientId: existingAppClient.ClientId,
      UserPoolId: existingAppClient.UserPoolId,
    });
    expect(kept.UserPoolClient?.RefreshTokenRotation?.Feature).toBe("ENABLED");
  });

  it.each([
    [
      { Feature: "ENABLED", RetryGracePeriodSeconds: 61 },
      "1 validation error detected: Value '61' at 'refreshTokenRotation.retryGracePeriodSeconds' failed to satisfy constraint: Member must have value less than or equal to 60",
    ],
    [
      { Feature: "ON", RetryGracePeriodSeconds: -1 },
      "2 validation errors detected: Value 'ON' at 'refreshTokenRotation.feature' failed to satisfy constraint: Member must satisfy enum value set: [ENABLED, DISABLED]; Value '-1' at 'refreshTokenRotation.retryGracePeriodSeconds' failed to satisfy constraint: Member must have value greater than or equal to 0",
    ],
  ])("refuses RefreshTokenRotation %j", async (rotation, message) => {
    const existingAppClient = TDB.appClient({ UserPoolId: "test" });
    mockCognitoService.getAppClient.mockResolvedValue(existingAppClient);

    await expect(
      updateUserPoolClient(TestContext, {
        ClientId: existingAppClient.ClientId,
        UserPoolId: existingAppClient.UserPoolId,
        RefreshTokenRotation: rotation as never,
      }),
    ).rejects.toEqual(new InvalidParameterError(message));
  });

  it("throws if the user pool client doesn't exist", async () => {
    mockCognitoService.getAppClient.mockResolvedValue(null);

    await expect(
      updateUserPoolClient(TestContext, {
        ClientId: "clientId",
        UserPoolId: "test",
      }),
    ).rejects.toEqual(new ResourceNotFoundError());
  });
});
