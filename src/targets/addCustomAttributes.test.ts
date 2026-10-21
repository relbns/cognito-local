import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError } from "../errors";
import type { CognitoService } from "../services";
import {
  AddCustomAttributes,
  type AddCustomAttributesTarget,
} from "./addCustomAttributes";

const originalDate = new Date();

describe("AddCustomAttributes target", () => {
  let addCustomAttributes: AddCustomAttributesTarget;
  let clock: ClockFake;
  let mockCognitoService: MockedObject<CognitoService>;

  beforeEach(() => {
    clock = new ClockFake(originalDate);

    mockCognitoService = newMockCognitoService();
    addCustomAttributes = AddCustomAttributes({
      clock,
      cognito: mockCognitoService,
    });
  });

  it("appends a custom attribute to the user pool", async () => {
    const userPool = TDB.userPool();
    const mockUserPoolService = newMockUserPoolService(userPool);

    mockCognitoService.getUserPool.mockResolvedValue(mockUserPoolService);

    const newDate = new Date();
    clock.advanceTo(newDate);

    await addCustomAttributes(TestContext, {
      UserPoolId: "test",
      CustomAttributes: [
        {
          AttributeDataType: "String",
          Name: "test",
        },
      ],
    });

    expect(mockUserPoolService.updateOptions).toHaveBeenCalledWith(
      TestContext,
      {
        ...userPool,
        SchemaAttributes: [
          ...(userPool.SchemaAttributes ?? []),
          {
            Name: "custom:test",
            AttributeDataType: "String",
            DeveloperOnlyAttribute: false,
            Mutable: true,
            Required: false,
            StringAttributeConstraints: {},
          },
        ],
        LastModifiedDate: newDate,
      },
    );
  });

  it.each([
    [0, "valid min length: 1"],
    [26, "valid max length: 25"],
  ])("refuses a list of %i attributes", async (count, limit) => {
    mockCognitoService.getUserPool.mockResolvedValue(
      newMockUserPoolService(TDB.userPool()),
    );

    await expect(
      addCustomAttributes(TestContext, {
        UserPoolId: "test",
        CustomAttributes: Array.from({ length: count }, (_, i) => ({
          AttributeDataType: "String",
          Name: `attr${i}`,
        })),
      }),
    ).rejects.toEqual(
      new InvalidParameterError(
        `Invalid length for parameter CustomAttributes, value: ${count}, ${limit}`,
      ),
    );
  });

  it("can create a custom attribute with no name", async () => {
    const userPool = TDB.userPool();
    const mockUserPoolService = newMockUserPoolService(userPool);

    mockCognitoService.getUserPool.mockResolvedValue(mockUserPoolService);

    const newDate = new Date();
    clock.advanceTo(newDate);

    await addCustomAttributes(TestContext, {
      UserPoolId: "test",
      CustomAttributes: [
        {
          AttributeDataType: "String",
        },
      ],
    });

    expect(mockUserPoolService.updateOptions).toHaveBeenCalledWith(
      TestContext,
      {
        ...userPool,
        SchemaAttributes: [
          ...(userPool.SchemaAttributes ?? []),
          {
            Name: "custom:null",
            AttributeDataType: "String",
            DeveloperOnlyAttribute: false,
            Mutable: true,
            Required: false,
            StringAttributeConstraints: {},
          },
        ],
        LastModifiedDate: newDate,
      },
    );
  });

  it("names a developer-only attribute dev:custom:<name>", async () => {
    const userPool = TDB.userPool();
    const mockUserPoolService = newMockUserPoolService(userPool);
    mockCognitoService.getUserPool.mockResolvedValue(mockUserPoolService);

    await addCustomAttributes(TestContext, {
      UserPoolId: "test",
      CustomAttributes: [
        {
          AttributeDataType: "String",
          DeveloperOnlyAttribute: true,
          Name: "tier",
        },
      ],
    });

    expect(mockUserPoolService.updateOptions).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        SchemaAttributes: [
          ...(userPool.SchemaAttributes ?? []),
          expect.objectContaining({
            Name: "dev:custom:tier",
            DeveloperOnlyAttribute: true,
          }),
        ],
      }),
    );
  });

  it("throws if a developer-only attribute reuses a custom attribute's name", async () => {
    const userPool = TDB.userPool({
      SchemaAttributes: [{ Name: "custom:tier", AttributeDataType: "String" }],
    });
    mockCognitoService.getUserPool.mockResolvedValue(
      newMockUserPoolService(userPool),
    );

    await expect(
      addCustomAttributes(TestContext, {
        UserPoolId: "test",
        CustomAttributes: [{ DeveloperOnlyAttribute: true, Name: "tier" }],
      }),
    ).rejects.toEqual(
      new InvalidParameterError(
        "dev:custom:tier: Existing attribute already has name dev:custom:tier.",
      ),
    );
  });

  it("throws if an attribute with the name already exists", async () => {
    const userPool = TDB.userPool({
      SchemaAttributes: [
        {
          Name: "custom:test",
          AttributeDataType: "String",
          DeveloperOnlyAttribute: false,
          Mutable: true,
          Required: false,
          StringAttributeConstraints: {},
        },
      ],
    });
    const mockUserPoolService = newMockUserPoolService(userPool);

    mockCognitoService.getUserPool.mockResolvedValue(mockUserPoolService);

    await expect(
      addCustomAttributes(TestContext, {
        UserPoolId: "test",
        CustomAttributes: [
          {
            AttributeDataType: "String",
            Name: "test",
          },
        ],
      }),
    ).rejects.toEqual(
      new InvalidParameterError(
        "custom:test: Existing attribute already has name custom:test.",
      ),
    );

    expect(mockUserPoolService.updateOptions).not.toHaveBeenCalled();
  });
});
