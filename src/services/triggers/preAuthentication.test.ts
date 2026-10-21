import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockLambda } from "../../__tests__/mockLambda";
import { newMockTriggers } from "../../__tests__/mockTriggers";
import { TestContext } from "../../__tests__/testContext";
import * as TDB from "../../__tests__/testDataBuilder";
import { UserLambdaValidationError } from "../../errors";
import type { Lambda } from "../lambda";
import { attributesToRecord } from "../userPoolService";
import {
  PreAuthentication,
  type PreAuthenticationTrigger,
  runPreAuthentication,
} from "./preAuthentication";
import type { Triggers } from "./triggers";

describe("PreAuthentication trigger", () => {
  let mockLambda: MockedObject<Lambda>;
  let preAuthentication: PreAuthenticationTrigger;
  const user = TDB.user();

  beforeEach(() => {
    mockLambda = newMockLambda();
    preAuthentication = PreAuthentication({ lambda: mockLambda });
  });

  it("invokes the lambda", async () => {
    mockLambda.invoke.mockResolvedValue({});

    await preAuthentication(TestContext, {
      clientId: "clientId",
      source: "PreAuthentication_Authentication",
      userAttributes: user.Attributes,
      userNotFound: false,
      username: user.Username,
      userPoolId: "userPoolId",
      validationData: { client: "metadata" },
    });

    expect(mockLambda.invoke).toHaveBeenCalledWith(
      TestContext,
      "PreAuthentication",
      {
        clientId: "clientId",
        triggerSource: "PreAuthentication_Authentication",
        userAttributes: attributesToRecord(user.Attributes),
        userNotFound: false,
        userPoolId: "userPoolId",
        username: user.Username,
        validationData: { client: "metadata" },
      },
    );
  });

  it("rethrows a lambda error so the sign-in fails", async () => {
    const error = new UserLambdaValidationError(
      "PreAuthentication failed with error blocked.",
    );
    mockLambda.invoke.mockRejectedValue(error);

    await expect(
      preAuthentication(TestContext, {
        clientId: "clientId",
        source: "PreAuthentication_Authentication",
        userAttributes: [],
        userNotFound: undefined,
        username: "jane",
        userPoolId: "userPoolId",
        validationData: undefined,
      }),
    ).rejects.toBe(error);
  });
});

describe("runPreAuthentication", () => {
  let mockTriggers: MockedObject<Triggers>;
  const user = TDB.user();

  beforeEach(() => {
    mockTriggers = newMockTriggers();
    mockTriggers.enabled.mockImplementation(
      (name) => name === "PreAuthentication",
    );
  });

  it("does nothing when the trigger is not configured", async () => {
    mockTriggers.enabled.mockReturnValue(false);

    await runPreAuthentication(TestContext, mockTriggers, {
      client: TDB.appClient(),
      user,
      username: user.Username,
      userPoolId: "test",
      validationData: undefined,
    });

    expect(mockTriggers.preAuthentication).not.toHaveBeenCalled();
  });

  it("runs for an existing user without userNotFound on a LEGACY client", async () => {
    const client = TDB.appClient();

    await runPreAuthentication(TestContext, mockTriggers, {
      client,
      user,
      username: "alias@example.test",
      userPoolId: "test",
      validationData: { client: "metadata" },
    });

    expect(mockTriggers.preAuthentication).toHaveBeenCalledWith(TestContext, {
      clientId: client.ClientId,
      source: "PreAuthentication_Authentication",
      userAttributes: user.Attributes,
      userNotFound: undefined,
      username: user.Username,
      userPoolId: "test",
      validationData: { client: "metadata" },
    });
  });

  it("skips an unknown user on a LEGACY client", async () => {
    await runPreAuthentication(TestContext, mockTriggers, {
      client: TDB.appClient(),
      user: null,
      username: "nobody",
      userPoolId: "test",
      validationData: undefined,
    });

    expect(mockTriggers.preAuthentication).not.toHaveBeenCalled();
  });

  it("runs for an unknown user with userNotFound when the client prevents user existence errors", async () => {
    await runPreAuthentication(TestContext, mockTriggers, {
      client: TDB.appClient({ PreventUserExistenceErrors: "ENABLED" }),
      user: null,
      username: "nobody",
      userPoolId: "test",
      validationData: undefined,
    });

    expect(mockTriggers.preAuthentication).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        userAttributes: [],
        userNotFound: true,
        username: "nobody",
      }),
    );
  });

  it("sets userNotFound false for a known user when the client prevents user existence errors", async () => {
    await runPreAuthentication(TestContext, mockTriggers, {
      client: TDB.appClient({ PreventUserExistenceErrors: "ENABLED" }),
      user,
      username: user.Username,
      userPoolId: "test",
      validationData: undefined,
    });

    expect(mockTriggers.preAuthentication).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({ userNotFound: false }),
    );
  });
});
