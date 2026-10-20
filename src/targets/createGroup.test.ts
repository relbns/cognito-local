import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { GroupExistsError } from "../errors";
import type { UserPoolService } from "../services";
import { CreateGroup, type CreateGroupTarget } from "./createGroup";

const originalDate = new Date();

describe("CreateGroup target", () => {
  let createGroup: CreateGroupTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    createGroup = CreateGroup({
      clock: new ClockFake(originalDate),
      cognito: newMockCognitoService(mockUserPoolService),
    });
  });

  it("creates a group", async () => {
    await createGroup(TestContext, {
      Description: "Description",
      GroupName: "theGroupName",
      Precedence: 1,
      RoleArn: "ARN",
      UserPoolId: "test",
    });

    expect(mockUserPoolService.saveGroup).toHaveBeenCalledWith(TestContext, {
      CreationDate: originalDate,
      Description: "Description",
      GroupName: "theGroupName",
      LastModifiedDate: originalDate,
      Precedence: 1,
      RoleArn: "ARN",
    });
  });

  it("throws GroupExistsException and keeps the existing group", async () => {
    mockUserPoolService.getGroupByGroupName.mockResolvedValue(
      TDB.group({ GroupName: "theGroupName", members: ["jane"] }),
    );

    await expect(
      createGroup(TestContext, {
        GroupName: "theGroupName",
        UserPoolId: "test",
      }),
    ).rejects.toEqual(new GroupExistsError("theGroupName"));
    expect(mockUserPoolService.saveGroup).not.toHaveBeenCalled();
  });
});
