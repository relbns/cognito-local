import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import {
  newMockDataStore,
  newMockDataStoreFactory,
} from "../__tests__/mockDataStore";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { NotAuthorizedError } from "../errors";
import type { AppClient } from "./appClient";
import type { DataStore } from "./dataStore/dataStore";
import type { Attribute } from "./sdkTypes";
import {
  attributesFromRecord,
  attributesInclude,
  attributesIncludeMatch,
  attributesToRecord,
  type Group,
  type User,
  type UserPool,
  type UserPoolService,
  UserPoolServiceFactoryImpl,
  UserPoolServiceImpl,
  validatePermittedAttributeChanges,
} from "./userPoolService";

describe("UserPoolServiceFactory", () => {
  it("creates a database", async () => {
    const mockDataStoreFactory = newMockDataStoreFactory(newMockDataStore());

    const clientsDataStore = newMockDataStore();
    const factory = new UserPoolServiceFactoryImpl(
      new ClockFake(new Date()),
      mockDataStoreFactory,
    );

    await factory.create(TestContext, clientsDataStore, {
      Id: "local",
      UsernameAttributes: [],
    });

    expect(mockDataStoreFactory.create).toHaveBeenCalledWith(
      TestContext,
      "local",
      {
        Options: { Id: "local", UsernameAttributes: [] },
        Users: {},
      },
    );
  });
});

describe("User Pool Service", () => {
  let mockClientsDataStore: MockedObject<DataStore>;
  const currentDate = new Date(2020, 1, 2, 3, 4, 5);

  let clock: ClockFake;

  beforeEach(() => {
    clock = new ClockFake(currentDate);

    mockClientsDataStore = newMockDataStore();
  });

  describe("saveAppClient", () => {
    it("saves an app client", async () => {
      const ds = newMockDataStore();
      ds.get.mockImplementation((_ctx, _key, defaults) =>
        Promise.resolve(defaults),
      );

      const userPool = new UserPoolServiceImpl(
        mockClientsDataStore,
        clock,
        ds,
        {
          Id: "local",
          UsernameAttributes: [],
        },
      );

      const appClient: AppClient = {
        ClientId: "clientId",
        ClientName: "clientName",
        CreationDate: currentDate,
        LastModifiedDate: currentDate,
        RefreshTokenValidity: 30,
        UserPoolId: "local",
      };

      await userPool.saveAppClient(TestContext, appClient);

      expect(mockClientsDataStore.set).toHaveBeenCalledWith(
        TestContext,
        ["Clients", "clientId"],
        appClient,
      );
    });
  });

  describe("saveGroup", () => {
    const group = TDB.group();

    it("saves the group", async () => {
      const ds = newMockDataStore();

      const userPool = new UserPoolServiceImpl(
        mockClientsDataStore,
        clock,
        ds,
        {
          Id: "local",
          UsernameAttributes: [],
        },
      );

      await userPool.saveGroup(TestContext, group);

      expect(ds.set).toHaveBeenCalledWith(
        TestContext,
        ["Groups", group.GroupName],
        group,
      );
    });
  });

  describe("saveUser", () => {
    const user = TDB.user();

    it("saves the user", async () => {
      const ds = newMockDataStore();

      const userPool = new UserPoolServiceImpl(
        mockClientsDataStore,
        clock,
        ds,
        {
          Id: "local",
          UsernameAttributes: [],
        },
      );

      await userPool.saveUser(TestContext, user);

      expect(ds.set).toHaveBeenCalledWith(
        TestContext,
        ["Users", user.Username],
        user,
      );
    });
  });

  describe("updateUser", () => {
    const loaded = TDB.user({ Attributes: [{ Name: "name", Value: "Old" }] });
    const stored = { ...loaded, Attributes: [{ Name: "name", Value: "New" }] };

    const newPool = (ds: MockedObject<DataStore>) =>
      new UserPoolServiceImpl(mockClientsDataStore, clock, ds, {
        Id: "local",
        UsernameAttributes: [],
      });

    it("applies the update to the stored record, not the loaded copy", async () => {
      const ds = newMockDataStore();
      ds.get.mockResolvedValue(stored);

      const result = await newPool(ds).updateUser(
        TestContext,
        loaded,
        (latest) => ({ ...latest, MFACode: "123456" }),
      );

      expect(ds.get).toHaveBeenCalledWith(TestContext, [
        "Users",
        loaded.Username,
      ]);
      expect(result).toEqual({ ...stored, MFACode: "123456" });
      expect(ds.set).toHaveBeenCalledWith(
        TestContext,
        ["Users", loaded.Username],
        result,
      );
    });

    it("falls back to the given user when nothing is stored", async () => {
      const ds = newMockDataStore();
      ds.get.mockResolvedValue(null);

      const result = await newPool(ds).updateUser(
        TestContext,
        loaded,
        (latest) => ({ ...latest, MFACode: "123456" }),
      );

      expect(result).toEqual({ ...loaded, MFACode: "123456" });
    });

    it("storeRefreshToken keeps changes made to the stored record", async () => {
      const ds = newMockDataStore();
      ds.get.mockResolvedValue(stored);

      await newPool(ds).storeRefreshToken(TestContext, "refresh", loaded);

      expect(ds.set).toHaveBeenCalledWith(
        TestContext,
        ["Users", loaded.Username],
        { ...stored, RefreshTokens: ["refresh"] },
      );
    });
  });

  describe("deleteAppClient", () => {
    const appClient = TDB.appClient();

    it("deletes the user pool client", async () => {
      const clientsDs = newMockDataStore();

      const userPool = new UserPoolServiceImpl(
        clientsDs,
        clock,
        newMockDataStore(),
        {
          Id: "local",
          UsernameAttributes: [],
        },
      );

      await userPool.deleteAppClient(TestContext, appClient);

      expect(clientsDs.delete).toHaveBeenCalledWith(TestContext, [
        "Clients",
        appClient.ClientId,
      ]);
    });
  });

  describe("deleteGroup", () => {
    const group = TDB.group();

    it("deletes the group", async () => {
      const ds = newMockDataStore();

      const userPool = new UserPoolServiceImpl(
        mockClientsDataStore,
        clock,
        ds,
        {
          Id: "local",
          UsernameAttributes: [],
        },
      );

      await userPool.deleteGroup(TestContext, group);

      expect(ds.delete).toHaveBeenCalledWith(TestContext, [
        "Groups",
        group.GroupName,
      ]);
    });
  });

  describe("deleteUser", () => {
    const user = TDB.user();

    it("deletes the user", async () => {
      const ds = newMockDataStore();

      ds.get.mockImplementation((_ctx, key) => {
        if (key === "Groups") {
          return Promise.resolve({});
        }

        return Promise.resolve(null);
      });

      const userPool = new UserPoolServiceImpl(
        mockClientsDataStore,
        clock,
        ds,
        {
          Id: "local",
          UsernameAttributes: [],
        },
      );

      await userPool.deleteUser(TestContext, user);

      expect(ds.delete).toHaveBeenCalledWith(TestContext, [
        "Users",
        user.Username,
      ]);
    });

    it("removes the user from any groups they're assigned to", async () => {
      const group1 = TDB.group({
        members: [user.Username],
      });
      const group2 = TDB.group({
        members: [user.Username],
      });
      const group3 = TDB.group();
      const groups = {
        [group1.GroupName]: group1,
        [group2.GroupName]: group2,
        [group3.GroupName]: group3,
      };

      const ds = newMockDataStore();
      ds.get.mockImplementation((_ctx, key) => {
        if (key === "Groups") {
          return Promise.resolve(groups);
        } else if (Array.isArray(key) && key[0] === "Groups") {
          return Promise.resolve(groups[key[1]]);
        }

        return Promise.resolve(null);
      });

      const userPool = new UserPoolServiceImpl(
        mockClientsDataStore,
        clock,
        ds,
        {
          Id: "local",
          UsernameAttributes: [],
        },
      );

      const newDate = new Date();
      clock.advanceTo(newDate);

      await userPool.deleteUser(TestContext, user);

      expect(ds.set).toHaveBeenCalledWith(
        TestContext,
        ["Groups", group1.GroupName],
        {
          ...group1,
          LastModifiedDate: newDate,
          members: [],
        },
      );
      expect(ds.set).toHaveBeenCalledWith(
        TestContext,
        ["Groups", group2.GroupName],
        {
          ...group2,
          LastModifiedDate: newDate,
          members: [],
        },
      );
      expect(ds.set).not.toHaveBeenCalledWith(TestContext, [
        "Groups",
        group3.GroupName,
      ]);
    });
  });

  describe("getGroupsByGroupName", () => {
    const group = TDB.group({
      GroupName: "1",
    });

    let userPool: UserPoolService;

    beforeEach(() => {
      const options = {
        Id: "local",
      };
      const groups: Record<string, Group> = {
        [group.GroupName]: group,
      };

      const ds = newMockDataStore();
      ds.get.mockImplementation((_ctx, key) => {
        if (key === "Groups") {
          return Promise.resolve(groups);
        } else if (key === "Options") {
          return Promise.resolve(options);
        } else if (Array.isArray(key) && key[0] === "Groups") {
          return Promise.resolve(groups[key[1]]);
        }

        return Promise.resolve(null);
      });

      userPool = new UserPoolServiceImpl(
        mockClientsDataStore,
        clock,
        ds,
        options,
      );
    });

    it("returns null if group doesn't exist", async () => {
      const foundGroup = await userPool.getGroupByGroupName(
        TestContext,
        "invalid",
      );

      expect(foundGroup).toBeNull();
    });

    it("returns existing group by their group name", async () => {
      const foundGroup = await userPool.getGroupByGroupName(
        TestContext,
        group.GroupName,
      );

      expect(foundGroup).toEqual(group);
    });
  });

  describe("getUserByUsername", () => {
    const user = TDB.user({
      Username: "1",
      Attributes: [
        { Name: "sub", Value: "uuid-1234" },
        { Name: "email", Value: "example@example.com" },
        { Name: "phone_number", Value: "0411000111" },
      ],
    });

    describe.each`
      username_attributes          | find_by_email | find_by_phone_number
      ${[]}                        | ${false}      | ${false}
      ${["email"]}                 | ${true}       | ${false}
      ${["phone_number"]}          | ${false}      | ${true}
      ${["email", "phone_number"]} | ${true}       | ${true}
    `(
      "$username_attributes username attributes",
      ({ username_attributes, find_by_email, find_by_phone_number }) => {
        let userPool: UserPoolService;

        beforeEach(() => {
          const options = {
            Id: "local",
            UsernameAttributes: username_attributes,
          };
          const users: Record<string, User> = {
            [user.Username]: user,
          };

          const ds = newMockDataStore();
          ds.get.mockImplementation((_ctx, key) => {
            if (key === "Users") {
              return Promise.resolve(users);
            } else if (key === "Options") {
              return Promise.resolve(options);
            } else if (Array.isArray(key) && key[0] === "Users") {
              return Promise.resolve(users[key[1]]);
            }

            return Promise.resolve(null);
          });

          userPool = new UserPoolServiceImpl(
            mockClientsDataStore,
            clock,
            ds,
            options,
          );
        });

        it("returns null if user doesn't exist", async () => {
          const user = await userPool.getUserByUsername(TestContext, "invalid");

          expect(user).toBeNull();
        });

        it("returns existing user by their username", async () => {
          const foundUser = await userPool.getUserByUsername(
            TestContext,
            user.Username,
          );

          expect(foundUser).toEqual(user);
        });

        it("returns existing user by their sub", async () => {
          const foundUser = await userPool.getUserByUsername(
            TestContext,
            "uuid-1234",
          );

          expect(foundUser).toEqual(user);
        });

        if (find_by_email) {
          it("returns existing user by their email", async () => {
            const foundUser = await userPool.getUserByUsername(
              TestContext,
              "example@example.com",
            );

            expect(foundUser).toEqual(foundUser);
          });
        } else {
          it("does not return the user by their email", async () => {
            const foundUser = await userPool.getUserByUsername(
              TestContext,
              "example@example.com",
            );

            expect(foundUser).toBeNull();
          });
        }

        if (find_by_phone_number) {
          it("returns existing user by their phone number", async () => {
            const foundUser = await userPool.getUserByUsername(
              TestContext,
              "0411000111",
            );

            expect(foundUser).toEqual(user);
          });
        } else {
          it("does not return the user by their phone number", async () => {
            const foundUser = await userPool.getUserByUsername(
              TestContext,
              "0411000111",
            );

            expect(foundUser).toBeNull();
          });
        }
      },
    );
  });

  describe("getUserByUsername with AliasAttributes", () => {
    const aliasUser = (verified: boolean) =>
      TDB.user({
        Username: "jane",
        Attributes: [
          { Name: "sub", Value: "uuid-alias" },
          { Name: "email", Value: "Jane@Example.test" },
          { Name: "email_verified", Value: String(verified) },
          { Name: "phone_number", Value: "+15555550100" },
          { Name: "phone_number_verified", Value: String(verified) },
          { Name: "preferred_username", Value: "JaneD" },
        ],
      });

    const poolWith = (options: UserPool, user: User) => {
      const users: Record<string, User> = { [user.Username]: user };
      const ds = newMockDataStore();
      ds.get.mockImplementation((_ctx, key) => {
        if (key === "Users") return Promise.resolve(users);
        if (Array.isArray(key) && key[0] === "Users") {
          return Promise.resolve(users[key[1]] ?? null);
        }
        return Promise.resolve(null);
      });
      return new UserPoolServiceImpl(mockClientsDataStore, clock, ds, options);
    };

    const allAliases: UserPool = {
      Id: "local",
      AliasAttributes: ["email", "phone_number", "preferred_username"],
    };

    it("finds the user by a verified email or phone number and by preferred_username", async () => {
      const user = aliasUser(true);
      const userPool = poolWith(allAliases, user);

      for (const alias of ["Jane@Example.test", "+15555550100", "JaneD"]) {
        expect(await userPool.getUserByUsername(TestContext, alias)).toEqual(
          user,
        );
      }
    });

    it("does not use an unverified email or phone number", async () => {
      const userPool = poolWith(allAliases, aliasUser(false));

      expect(
        await userPool.getUserByUsername(TestContext, "Jane@Example.test"),
      ).toBeNull();
      expect(
        await userPool.getUserByUsername(TestContext, "+15555550100"),
      ).toBeNull();
      expect(
        await userPool.getUserByUsername(TestContext, "JaneD"),
      ).not.toBeNull();
    });

    it("only uses the attributes the pool names as aliases", async () => {
      const userPool = poolWith(
        { Id: "local", AliasAttributes: ["preferred_username"] },
        aliasUser(true),
      );

      expect(
        await userPool.getUserByUsername(TestContext, "Jane@Example.test"),
      ).toBeNull();
      expect(
        await userPool.getUserByUsername(TestContext, "JaneD"),
      ).not.toBeNull();
    });

    it("matches email and preferred_username in any case when the pool is case-insensitive", async () => {
      const user = aliasUser(true);
      const caseSensitive = poolWith(allAliases, user);
      const caseInsensitive = poolWith(
        { ...allAliases, UsernameConfiguration: { CaseSensitive: false } },
        user,
      );

      expect(
        await caseSensitive.getUserByUsername(TestContext, "jane@example.test"),
      ).toBeNull();
      expect(
        await caseInsensitive.getUserByUsername(
          TestContext,
          "jane@example.test",
        ),
      ).toEqual(user);
      expect(
        await caseInsensitive.getUserByUsername(TestContext, "janed"),
      ).toEqual(user);
    });
  });

  describe("UsernameConfiguration.CaseSensitive", () => {
    const user = TDB.user({
      Username: "Jane",
      Attributes: [
        { Name: "sub", Value: "uuid-1234" },
        { Name: "email", Value: "Jane@Example.test" },
        { Name: "preferred_username", Value: "JaneD" },
        { Name: "phone_number", Value: "+15555550100" },
      ],
    });

    const poolWith = (options: UserPool) => {
      const users: Record<string, User> = { [user.Username]: user };
      const ds = newMockDataStore();
      ds.get.mockImplementation((_ctx, key) => {
        if (key === "Users") return Promise.resolve(users);
        if (Array.isArray(key) && key[0] === "Users") {
          return Promise.resolve(users[key[1]] ?? null);
        }
        return Promise.resolve(null);
      });
      return new UserPoolServiceImpl(mockClientsDataStore, clock, ds, options);
    };

    describe("false", () => {
      const options: UserPool = {
        Id: "local",
        UsernameAttributes: ["email"],
        UsernameConfiguration: { CaseSensitive: false },
      };

      it.each([
        "Jane",
        "jane",
        "JANE",
        "jane@example.test",
        "JANE@EXAMPLE.TEST",
      ])("finds the user by %s", async (username) => {
        expect(
          await poolWith(options).getUserByUsername(TestContext, username),
        ).toEqual(user);
      });

      it.each([
        'username = "jane"',
        'username ^= "JA"',
        'email = "jane@example.test"',
        'preferred_username = "janed"',
      ])("matches ListUsers filter %s in any case", async (filter) => {
        expect(await poolWith(options).listUsers(TestContext, filter)).toEqual([
          user,
        ]);
      });
    });

    describe("true or unset", () => {
      it.each([
        { Id: "local", UsernameAttributes: ["email"] },
        {
          Id: "local",
          UsernameAttributes: ["email"],
          UsernameConfiguration: { CaseSensitive: true },
        },
      ] as UserPool[])("matches the exact case only", async (options) => {
        const pool = poolWith(options);
        expect(await pool.getUserByUsername(TestContext, "jane")).toBeNull();
        expect(
          await pool.getUserByUsername(TestContext, "jane@example.test"),
        ).toBeNull();
        expect(
          await pool.getUserByUsername(TestContext, "Jane@Example.test"),
        ).toEqual(user);
        expect(await pool.listUsers(TestContext, 'username = "jane"')).toEqual(
          [],
        );
      });
    });
  });

  describe("listUsers", () => {
    const user1 = TDB.user({
      Username: "1",
    });
    const user2 = TDB.user({
      Username: "2",
    });

    let userPool: UserPoolService;

    beforeEach(() => {
      const options = {
        Id: "local",
      };

      const users = {
        [user1.Username]: user1,
        [user2.Username]: user2,
      };

      const ds = newMockDataStore();
      ds.get.mockImplementation((_ctx, key) => {
        if (key === "Users") {
          return Promise.resolve(users);
        } else if (key === "Options") {
          return Promise.resolve(options);
        }

        return Promise.resolve(null);
      });
      userPool = new UserPoolServiceImpl(mockClientsDataStore, clock, ds, {
        Id: "local",
        UsernameAttributes: [],
      });
    });

    it("returns existing users", async () => {
      const users = await userPool.listUsers(TestContext);

      expect(users).not.toBeNull();
      expect(users).toEqual([user1, user2]);
    });

    it("can filter users", async () => {
      const users = await userPool.listUsers(TestContext, 'username = "2"');

      expect(users).not.toBeNull();
      expect(users).toEqual([user2]);
    });
  });

  describe("attributes", () => {
    const attributes: Attribute[] = [
      { Name: "email", Value: "example@example.com" },
      { Name: "sub", Value: "uuid" },
    ];

    describe("attributesIncludeMatch", () => {
      it("returns true if attribute exists in collection with matching name and value", () => {
        expect(
          attributesIncludeMatch("email", "example@example.com", attributes),
        ).toBe(true);
      });

      it("returns false if attribute exists in collection with matching name but not matching value", () => {
        expect(attributesIncludeMatch("email", "invalid", attributes)).toBe(
          false,
        );
      });

      it("returns false if attribute does not exist in collection", () => {
        expect(attributesIncludeMatch("invalid", "invalid", attributes)).toBe(
          false,
        );
      });
    });

    describe("attributesInclude", () => {
      it("returns true if attribute exists in collection with matching name", () => {
        expect(attributesInclude("email", attributes)).toBe(true);
      });

      it("returns false if attribute does not exist in collection", () => {
        expect(attributesInclude("invalid", attributes)).toBe(false);
      });
    });

    describe("attributesToRecord", () => {
      it("converts the attributes to a record", () => {
        expect(attributesToRecord(attributes)).toEqual({
          sub: "uuid",
          email: "example@example.com",
        });
      });
    });

    describe("attributesFromRecord", () => {
      it("converts the attributes to a record", () => {
        expect(
          attributesFromRecord({
            sub: "uuid",
            email: "example@example.com",
          }),
        ).toEqual(attributes);
      });
    });
  });

  describe("saveGroup", () => {
    it("saves the group", async () => {
      const now = new Date();
      const ds = newMockDataStore();

      const userPool = new UserPoolServiceImpl(
        mockClientsDataStore,
        clock,
        ds,
        {
          Id: "local",
          UsernameAttributes: [],
        },
      );

      await userPool.saveGroup(TestContext, {
        CreationDate: now,
        Description: "Description",
        GroupName: "theGroupName",
        LastModifiedDate: now,
        Precedence: 1,
        RoleArn: "ARN",
      });

      expect(ds.set).toHaveBeenCalledWith(
        TestContext,
        ["Groups", "theGroupName"],
        {
          CreationDate: now,
          Description: "Description",
          GroupName: "theGroupName",
          LastModifiedDate: now,
          Precedence: 1,
          RoleArn: "ARN",
        },
      );
    });
  });

  describe("listGroups", () => {
    let userPool: UserPoolService;

    beforeEach(() => {
      const options = {
        Id: "local",
      };
      const groups: Record<string, Group> = {
        theGroupName: {
          CreationDate: new Date(),
          Description: "Description",
          GroupName: "theGroupName",
          LastModifiedDate: new Date(),
          Precedence: 1,
          RoleArn: "ARN",
        },
      };

      const ds = newMockDataStore();
      ds.get.mockImplementation((_ctx, key) => {
        if (key === "Groups") {
          return Promise.resolve(groups);
        } else if (key === "Options") {
          return Promise.resolve(options);
        }

        return Promise.resolve(null);
      });
      userPool = new UserPoolServiceImpl(
        mockClientsDataStore,
        clock,
        ds,
        options,
      );
    });

    it("returns existing groups", async () => {
      const groups = await userPool.listGroups(TestContext);

      expect(groups).not.toBeNull();
      expect(groups).toHaveLength(1);
      expect(groups[0].GroupName).toEqual("theGroupName");
    });
  });

  describe("updateOptions", () => {
    it("updates the options in the datastore", async () => {
      const ds = newMockDataStore();
      const userPool = new UserPoolServiceImpl(
        mockClientsDataStore,
        clock,
        ds,
        {
          Id: "test",
        },
      );

      await userPool.updateOptions(TestContext, {
        Id: "test",
        MfaConfiguration: "ON",
      });

      expect(ds.set).toHaveBeenCalledWith(TestContext, "Options", {
        Id: "test",
        MfaConfiguration: "ON",
      });
    });

    it("updates the cached options", async () => {
      const ds = newMockDataStore();
      const userPool = new UserPoolServiceImpl(
        mockClientsDataStore,
        clock,
        ds,
        {
          Id: "test",
        },
      );

      await userPool.updateOptions(TestContext, {
        Id: "test",
        MfaConfiguration: "ON",
      });

      expect(userPool.options.MfaConfiguration).toEqual("ON");
    });
  });

  describe("addUserToGroup", () => {
    it("updates the group's members", async () => {
      const ds = newMockDataStore();
      const userPool = new UserPoolServiceImpl(
        mockClientsDataStore,
        clock,
        ds,
        {
          Id: "test",
        },
      );

      const user = TDB.user();
      const group = TDB.group();

      await userPool.addUserToGroup(TestContext, group, user);

      expect(ds.set).toHaveBeenCalledWith(
        TestContext,
        ["Groups", group.GroupName],
        {
          ...group,
          LastModifiedDate: clock.get(),
          members: [user.Username],
        },
      );
    });

    it("only adds the user once", async () => {
      const ds = newMockDataStore();
      const userPool = new UserPoolServiceImpl(
        mockClientsDataStore,
        clock,
        ds,
        {
          Id: "test",
        },
      );

      const user = TDB.user();
      const group = TDB.group({
        members: [user.Username],
      });

      await userPool.addUserToGroup(TestContext, group, user);

      expect(ds.set).not.toHaveBeenCalled();
    });
  });

  describe("removeUserFromGroup", () => {
    it("updates the group's members", async () => {
      const ds = newMockDataStore();
      const userPool = new UserPoolServiceImpl(
        mockClientsDataStore,
        clock,
        ds,
        {
          Id: "test",
        },
      );

      const user = TDB.user();
      const group = TDB.group({
        members: [user.Username],
      });

      await userPool.removeUserFromGroup(TestContext, group, user);

      expect(ds.set).toHaveBeenCalledWith(
        TestContext,
        ["Groups", group.GroupName],
        {
          ...group,
          LastModifiedDate: clock.get(),
          members: [],
        },
      );
    });
  });

  describe("listUserGroupMembership", () => {
    it("returns all the groups that the user is a member", async () => {
      const ds = newMockDataStore();
      const userPool = new UserPoolServiceImpl(
        mockClientsDataStore,
        clock,
        ds,
        {
          Id: "test",
        },
      );

      const user = TDB.user();
      const group1 = TDB.group({
        GroupName: "Group1",
        members: [user.Username],
      });
      const group2 = TDB.group({
        GroupName: "Group2",
        members: [user.Username],
      });
      const group3 = TDB.group({
        GroupName: "Group3",
        members: [],
      });
      const groups = {
        [group1.GroupName]: group1,
        [group2.GroupName]: group2,
        [group3.GroupName]: group3,
      };

      ds.get.mockImplementation((_ctx, key) => {
        if (key === "Groups") {
          return Promise.resolve(groups);
        }

        return Promise.resolve(null);
      });

      const groupMembership = await userPool.listUserGroupMembership(
        TestContext,
        user,
      );

      expect(groupMembership).toEqual([group1.GroupName, group2.GroupName]);
    });
  });

  describe("validatePermittedAttributeChanges", () => {
    const schema = [
      { Name: "dev:custom:tier", DeveloperOnlyAttribute: true, Mutable: true },
      { Name: "custom:team", Mutable: true },
    ];

    it("refuses a developer-only attribute in a user-level change", () => {
      expect(() =>
        validatePermittedAttributeChanges(
          [{ Name: "dev:custom:tier", Value: "gold" }],
          schema,
        ),
      ).toThrow(
        new NotAuthorizedError(
          "A client attempted to write unauthorized attribute",
        ),
      );
    });

    it("lets an administrator change a developer-only attribute", () => {
      const changes = [{ Name: "dev:custom:tier", Value: "gold" }];
      expect(
        validatePermittedAttributeChanges(changes, schema, { admin: true }),
      ).toEqual(changes);
    });

    it("lets a user change an ordinary custom attribute", () => {
      const changes = [{ Name: "custom:team", Value: "blue" }];
      expect(validatePermittedAttributeChanges(changes, schema)).toEqual(
        changes,
      );
    });
  });
});
