import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { UserLambdaValidationError } from "../errors";
import type { Triggers, UserPoolService } from "../services";
import { attributeValue, type User } from "../services/userPoolService";
import { federatedSignIn } from "./federatedSignIn";
import type { Claims, IdentityProviderConfig } from "./federation";

const google: IdentityProviderConfig = {
  ProviderName: "Google",
  ProviderType: "Google",
  AttributeMapping: {
    email: "email",
    email_verified: "email_verified",
    name: "name",
    username: "sub",
  },
};

const claims: Claims = {
  sub: "1234",
  email: "jane@gmail.com",
  email_verified: "true",
  name: "Jane Doe",
  hd: "ignored",
};

describe("federatedSignIn", () => {
  const now = new Date(2026, 9, 20, 12, 0, 0);
  let clock: ClockFake;
  let triggers: MockedObject<Triggers>;
  let userPool: MockedObject<UserPoolService>;
  const appClient = TDB.appClient({ ClientId: "client-1" });
  let saved: User[];

  beforeEach(() => {
    clock = new ClockFake(now);
    triggers = newMockTriggers();
    triggers.enabled.mockReturnValue(false);
    userPool = newMockUserPoolService({ Id: "pool-1" });
    userPool.listUsers.mockResolvedValue([]);
    userPool.getUserByUsername.mockResolvedValue(null);
    saved = [];
    userPool.saveUser.mockImplementation(async (_ctx, user) => {
      saved.push(user);
    });
  });

  const signIn = (provider = google, presented: Claims = claims) =>
    federatedSignIn(
      TestContext,
      { clock, triggers },
      userPool,
      appClient,
      provider,
      presented,
    );

  it("creates Google_<sub> with mapped attributes and a primary identity", async () => {
    const { user, outcome } = await signIn();

    expect(outcome).toBe("created");
    expect(user.Username).toBe("Google_1234");
    expect(user.UserStatus).toBe("EXTERNAL_PROVIDER");
    expect(attributeValue("email", user.Attributes)).toBe("jane@gmail.com");
    expect(attributeValue("email_verified", user.Attributes)).toBe("true");
    expect(attributeValue("name", user.Attributes)).toBe("Jane Doe");
    expect(attributeValue("hd", user.Attributes)).toBeUndefined();
    expect(attributeValue("sub", user.Attributes)).toMatch(/^[0-9a-f-]{36}$/);
    expect(
      JSON.parse(attributeValue("identities", user.Attributes) ?? ""),
    ).toEqual([
      {
        userId: "1234",
        providerName: "Google",
        providerType: "Google",
        issuer: null,
        primary: true,
        dateCreated: now.getTime(),
      },
    ]);
    expect(saved).toEqual([user]);
  });

  it("uses the OIDC issuer and the mapped username claim", async () => {
    const oidc: IdentityProviderConfig = {
      ProviderName: "ExampleOIDC",
      ProviderType: "OIDC",
      ProviderDetails: { oidc_issuer: "https://idp.example.test" },
      AttributeMapping: { username: "oid", email: "mail" },
    };
    const { user } = await signIn(oidc, {
      sub: "s",
      oid: "abc",
      mail: "a@b.c",
    });
    expect(user.Username).toBe("ExampleOIDC_abc");
    expect(attributeValue("email", user.Attributes)).toBe("a@b.c");
    expect(
      JSON.parse(attributeValue("identities", user.Attributes) ?? "")[0].issuer,
    ).toBe("https://idp.example.test");
  });

  it("runs PreSignUp_ExternalProvider and PostConfirmation on first sign-in", async () => {
    triggers.enabled.mockReturnValue(true);
    triggers.preSignUp.mockResolvedValue({
      autoConfirmUser: true,
      autoVerifyEmail: true,
      autoVerifyPhone: false,
    });

    const { user } = await signIn(
      { ...google, AttributeMapping: { email: "email" } },
      { sub: "1234", email: "jane@gmail.com" },
    );

    expect(triggers.preSignUp).toHaveBeenCalledWith(TestContext, {
      clientId: "client-1",
      clientMetadata: undefined,
      source: "PreSignUp_ExternalProvider",
      userAttributes: [{ Name: "email", Value: "jane@gmail.com" }],
      username: "Google_1234",
      userPoolId: "pool-1",
      validationData: undefined,
    });
    expect(attributeValue("email_verified", user.Attributes)).toBe("true");
    expect(triggers.postConfirmation).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        source: "PostConfirmation_ConfirmSignUp",
        username: "Google_1234",
      }),
    );
    expect(triggers.postAuthentication).not.toHaveBeenCalled();
  });

  it("creates no user when PreSignUp throws", async () => {
    triggers.enabled.mockImplementation((name) => name === "PreSignUp");
    triggers.preSignUp.mockRejectedValue(
      new UserLambdaValidationError("PreSignUp failed with error Blocked."),
    );

    await expect(signIn()).rejects.toThrow(
      "PreSignUp failed with error Blocked.",
    );
    expect(userPool.saveUser).not.toHaveBeenCalled();
  });

  it("reuses an existing federated user, refreshes mapped attributes and runs PostAuthentication", async () => {
    triggers.enabled.mockReturnValue(true);
    const existing = TDB.user({
      Username: "Google_1234",
      UserStatus: "EXTERNAL_PROVIDER",
      Attributes: [
        { Name: "sub", Value: "fixed-sub" },
        { Name: "name", Value: "Old Name" },
      ],
    });
    userPool.getUserByUsername.mockImplementation(
      async () => saved.at(-1) ?? existing,
    );

    const { user, outcome } = await signIn();

    expect(outcome).toBe("existing");
    expect(attributeValue("sub", user.Attributes)).toBe("fixed-sub");
    expect(attributeValue("name", user.Attributes)).toBe("Jane Doe");
    expect(triggers.preSignUp).not.toHaveBeenCalled();
    expect(triggers.postConfirmation).not.toHaveBeenCalled();
    expect(triggers.postAuthentication).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        source: "PostAuthentication_Authentication",
        username: "Google_1234",
      }),
    );
  });

  it("returns the user as stored after PostAuthentication changed it", async () => {
    triggers.enabled.mockImplementation(
      (name) => name === "PostAuthentication",
    );
    const existing = TDB.user({
      Username: "Google_1234",
      UserStatus: "EXTERNAL_PROVIDER",
    });
    const changedByTrigger = TDB.user({
      ...existing,
      Attributes: [{ Name: "custom:tier", Value: "gold" }],
    });
    userPool.getUserByUsername
      .mockResolvedValueOnce(existing)
      .mockResolvedValueOnce(changedByTrigger);

    const { user } = await signIn();

    expect(user).toEqual(changedByTrigger);
  });

  it("returns the user as stored after PostConfirmation changed it", async () => {
    triggers.enabled.mockImplementation((name) => name === "PostConfirmation");
    const changedByTrigger = TDB.user({
      Username: "Google_1234",
      Attributes: [{ Name: "custom:tier", Value: "gold" }],
    });
    userPool.getUserByUsername
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(changedByTrigger);

    const { user, outcome } = await signIn();

    expect(outcome).toBe("created");
    expect(user).toEqual(changedByTrigger);
  });

  it("refuses a disabled federated user", async () => {
    userPool.getUserByUsername.mockResolvedValue(
      TDB.user({ Username: "Google_1234", Enabled: false }),
    );
    await expect(signIn()).rejects.toThrow("User is disabled.");
  });

  it("signs in the native user linked with Cognito_Subject", async () => {
    const native = TDB.user({
      Username: "jane",
      ProviderLinks: [
        {
          providerName: "Google",
          attributeName: "Cognito_Subject",
          attributeValue: "1234",
        },
      ],
    });
    userPool.listUsers.mockResolvedValue([native]);

    const { user, outcome } = await signIn();

    expect(outcome).toBe("linked");
    expect(user.Username).toBe("jane");
    expect(attributeValue("name", user.Attributes)).toBe("Jane Doe");
    expect(userPool.getUserByUsername).not.toHaveBeenCalled();
  });

  it("matches a link made on a provider attribute", async () => {
    const native = TDB.user({
      Username: "carlos",
      ProviderLinks: [
        {
          providerName: "Google",
          attributeName: "email",
          attributeValue: "jane@gmail.com",
        },
      ],
    });
    userPool.listUsers.mockResolvedValue([native]);
    const { user } = await signIn();
    expect(user.Username).toBe("carlos");
  });

  it("signs in the linked user when PreSignUp links the identity", async () => {
    triggers.enabled.mockImplementation((name) => name === "PreSignUp");
    const native = TDB.user({
      Username: "jane",
      ProviderLinks: [
        {
          providerName: "Google",
          attributeName: "Cognito_Subject",
          attributeValue: "1234",
        },
      ],
    });
    userPool.listUsers
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([native]);
    triggers.preSignUp.mockResolvedValue({
      autoConfirmUser: false,
      autoVerifyEmail: false,
      autoVerifyPhone: false,
    });

    const { user, outcome } = await signIn();
    expect(outcome).toBe("linked");
    expect(user.Username).toBe("jane");
  });

  it("rejects a response without a subject", async () => {
    await expect(signIn(google, { email: "x@y.z" })).rejects.toThrow(
      "no subject",
    );
  });
});
