import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { AliasExistsError, UsernameExistsError } from "../errors";
import {
  aliasAttributesTouchedBy,
  enforceAliasUniqueness,
  isActiveAlias,
} from "./aliases";
import {
  attribute,
  attributesAppend,
  type UserPoolService,
} from "./userPoolService";

const phone = "+15555555555";
const verifiedPhone = [
  attribute("phone_number", phone),
  attribute("phone_number_verified", "true"),
];

describe("isActiveAlias", () => {
  it("requires email and phone_number to be verified", () => {
    expect(isActiveAlias("phone_number", verifiedPhone)).toBe(true);
    expect(
      isActiveAlias("phone_number", [attribute("phone_number", phone)]),
    ).toBe(false);
  });

  it("treats any preferred_username value as active", () => {
    expect(
      isActiveAlias("preferred_username", [
        attribute("preferred_username", "jane"),
      ]),
    ).toBe(true);
  });
});

describe("aliasAttributesTouchedBy", () => {
  it("maps verification flags to their attribute", () => {
    expect(
      aliasAttributesTouchedBy([
        attribute("email_verified", "true"),
        attribute("name", "x"),
        attribute("preferred_username", "jane"),
      ]),
    ).toEqual(["email", "preferred_username"]);
  });
});

describe("enforceAliasUniqueness", () => {
  let userPool: MockedObject<UserPoolService>;
  const clock = new ClockFake(new Date());
  const other = TDB.user({ Username: "other", Attributes: verifiedPhone });

  beforeEach(() => {
    userPool = newMockUserPoolService({
      Id: "test",
      AliasAttributes: ["phone_number", "preferred_username"],
    });
    userPool.listUsers.mockResolvedValue([other]);
    userPool.getUserByUsername.mockResolvedValue(other);
  });

  it("allows a duplicate value that is not verified", async () => {
    await enforceAliasUniqueness(TestContext, userPool, clock, "new", [
      attribute("phone_number", phone),
    ]);
    expect(userPool.saveUser).not.toHaveBeenCalled();
  });

  it("ignores another user whose duplicate value is not verified", async () => {
    userPool.listUsers.mockResolvedValue([
      TDB.user({
        Username: "other",
        Attributes: [attribute("phone_number", phone)],
      }),
    ]);
    await enforceAliasUniqueness(
      TestContext,
      userPool,
      clock,
      "new",
      verifiedPhone,
    );
    expect(userPool.saveUser).not.toHaveBeenCalled();
  });

  it("throws AliasExistsException for a verified duplicate", async () => {
    await expect(
      enforceAliasUniqueness(
        TestContext,
        userPool,
        clock,
        "new",
        verifiedPhone,
      ),
    ).rejects.toEqual(new AliasExistsError("phone_number"));
  });

  it("moves the alias and marks it unverified on the other user when forced", async () => {
    await enforceAliasUniqueness(
      TestContext,
      userPool,
      clock,
      "new",
      verifiedPhone,
      { forceAliasCreation: true },
    );
    expect(userPool.saveUser).toHaveBeenCalledWith(TestContext, {
      ...other,
      Attributes: attributesAppend(
        other.Attributes,
        attribute("phone_number_verified", "false"),
      ),
      UserLastModifiedDate: clock.get(),
    });
  });

  it("never forces a duplicate preferred_username", async () => {
    userPool.listUsers.mockResolvedValue([
      TDB.user({
        Username: "other",
        Attributes: [attribute("preferred_username", "jane")],
      }),
    ]);
    await expect(
      enforceAliasUniqueness(
        TestContext,
        userPool,
        clock,
        "new",
        [attribute("preferred_username", "jane")],
        { forceAliasCreation: true },
      ),
    ).rejects.toEqual(new AliasExistsError("preferred_username"));
  });

  it("only checks the requested attributes", async () => {
    await enforceAliasUniqueness(
      TestContext,
      userPool,
      clock,
      "new",
      verifiedPhone,
      { attributeNames: ["preferred_username"] },
    );
    expect(userPool.saveUser).not.toHaveBeenCalled();
  });

  describe("username attributes", () => {
    beforeEach(() => {
      userPool = newMockUserPoolService({
        Id: "test",
        UsernameAttributes: ["email"],
      });
      userPool.listUsers.mockResolvedValue([
        TDB.user({
          Username: "other",
          Attributes: [attribute("email", "a@example.com")],
        }),
      ]);
    });

    it("rejects a duplicate even when neither value is verified", async () => {
      await expect(
        enforceAliasUniqueness(TestContext, userPool, clock, "new", [
          attribute("email", "a@example.com"),
        ]),
      ).rejects.toEqual(new AliasExistsError("email"));
    });

    it("can report the duplicate as UsernameExistsException and ignores force", async () => {
      await expect(
        enforceAliasUniqueness(
          TestContext,
          userPool,
          clock,
          "new",
          [attribute("email", "a@example.com")],
          {
            forceAliasCreation: true,
            usernameConflict: "UsernameExistsException",
          },
        ),
      ).rejects.toEqual(
        new UsernameExistsError(
          "An account with the given email already exists.",
        ),
      );
    });
  });
});
