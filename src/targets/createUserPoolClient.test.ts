import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import { InvalidParameterError } from "../errors";
import type { UserPoolService } from "../services";
import {
  CreateUserPoolClient,
  type CreateUserPoolClientTarget,
} from "./createUserPoolClient";

const originalDate = new Date();

describe("CreateUserPoolClient target", () => {
  let createUserPoolClient: CreateUserPoolClientTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    createUserPoolClient = CreateUserPoolClient({
      clock: new ClockFake(originalDate),
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it("creates a new app client", async () => {
    const result = await createUserPoolClient(TestContext, {
      ClientName: "clientName",
      UserPoolId: "userPoolId",
    });

    expect(mockUserPoolService.saveAppClient).toHaveBeenCalledWith(
      TestContext,
      {
        ClientId: expect.any(String),
        ClientName: "clientName",
        CreationDate: originalDate,
        LastModifiedDate: originalDate,
        EnableTokenRevocation: true,
        UserPoolId: "userPoolId",
        TokenValidityUnits: {
          AccessToken: "hours",
          IdToken: "hours",
          RefreshToken: "days",
        },
      },
    );

    expect(result).toEqual({
      UserPoolClient: {
        ClientId: expect.any(String),
        ClientName: "clientName",
        CreationDate: originalDate,
        LastModifiedDate: originalDate,
        EnableTokenRevocation: true,
        UserPoolId: "userPoolId",
        TokenValidityUnits: {
          AccessToken: "hours",
          IdToken: "hours",
          RefreshToken: "days",
        },
      },
    });
  });

  it.each([
    [
      {
        AccessTokenValidity: 4,
        TokenValidityUnits: { AccessToken: "minutes" },
      },
    ],
    [{ AccessTokenValidity: 25 }],
    [{ IdTokenValidity: 25 }],
    [{ RefreshTokenValidity: 3651 }],
    [
      {
        RefreshTokenValidity: 59,
        TokenValidityUnits: { RefreshToken: "minutes" },
      },
    ],
  ] as const)(
    "rejects token validity outside AWS's range: %j",
    async (validity) => {
      await expect(
        createUserPoolClient(TestContext, {
          ClientName: "clientName",
          UserPoolId: "userPoolId",
          ...validity,
        }),
      ).rejects.toEqual(
        new InvalidParameterError("Invalid range for token validity."),
      );
    },
  );

  it("accepts token validity at the edges of AWS's range", async () => {
    await createUserPoolClient(TestContext, {
      ClientName: "clientName",
      UserPoolId: "userPoolId",
      AccessTokenValidity: 5,
      IdTokenValidity: 1,
      RefreshTokenValidity: 60,
      TokenValidityUnits: {
        AccessToken: "minutes",
        IdToken: "days",
        RefreshToken: "minutes",
      },
    });

    expect(mockUserPoolService.saveAppClient).toHaveBeenCalled();
  });

  it("stores and returns AuthSessionValidity", async () => {
    const result = await createUserPoolClient(TestContext, {
      ClientName: "clientName",
      UserPoolId: "userPoolId",
      AuthSessionValidity: 10,
    });

    expect(mockUserPoolService.saveAppClient).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({ AuthSessionValidity: 10 }),
    );
    expect(result.UserPoolClient?.AuthSessionValidity).toEqual(10);
  });

  it.each([
    [2, "greater than or equal to 3"],
    [16, "less than or equal to 15"],
  ])("rejects AuthSessionValidity %d", async (value, constraint) => {
    await expect(
      createUserPoolClient(TestContext, {
        ClientName: "clientName",
        UserPoolId: "userPoolId",
        AuthSessionValidity: value,
      }),
    ).rejects.toEqual(
      new InvalidParameterError(
        `1 validation error detected: Value '${value}' at 'authSessionValidity' failed to satisfy constraint: Member must have value ${constraint}`,
      ),
    );
    expect(mockUserPoolService.saveAppClient).not.toHaveBeenCalled();
  });
});
