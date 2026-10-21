import { describe, expect, it } from "vitest";
import {
  applyPreTokenGenerationResponse,
  groupConfigurationFor,
  preTokenGenerationVersion,
} from "./tokenCustomization";

const CLIENT_ID = "client-1";

const tokens = () => ({
  idToken: {
    sub: "user-sub",
    "cognito:username": "jane",
    email: "jane@example.test",
    email_verified: true,
    "cognito:groups": ["readers"],
    "cognito:roles": ["arn:aws:iam::000000000000:role/readers"],
    "cognito:preferred_role": "arn:aws:iam::000000000000:role/readers",
    "dev:internal": "dev-value",
  },
  accessToken: {
    sub: "user-sub",
    username: "jane",
    client_id: CLIENT_ID,
    scope: "openid email aws.cognito.signin.user.admin",
    "cognito:groups": ["readers"],
  },
});

describe("preTokenGenerationVersion", () => {
  it.each([
    [undefined, "1"],
    [{}, "1"],
    [{ PreTokenGeneration: "arn" }, "1"],
    [
      { PreTokenGenerationConfig: { LambdaArn: "a", LambdaVersion: "V1_0" } },
      "1",
    ],
    [
      { PreTokenGenerationConfig: { LambdaArn: "a", LambdaVersion: "V2_0" } },
      "2",
    ],
    [
      { PreTokenGenerationConfig: { LambdaArn: "a", LambdaVersion: "V3_0" } },
      "3",
    ],
    [
      { PreTokenGenerationConfig: { LambdaArn: "a", LambdaVersion: "V9" } },
      "1",
    ],
  ])("reads %j as version %s", (config, version) => {
    expect(preTokenGenerationVersion(config)).toBe(version);
  });
});

describe("groupConfigurationFor", () => {
  it("is empty without groups", () => {
    expect(groupConfigurationFor([])).toEqual({
      groupsToOverride: [],
      iamRolesToOverride: [],
      preferredRole: null,
    });
  });

  it("prefers the role of the group with the lowest precedence", () => {
    expect(
      groupConfigurationFor([
        { GroupName: "a", RoleArn: "role-a", Precedence: 5 },
        { GroupName: "b", RoleArn: "role-b", Precedence: 1 },
        { GroupName: "c" },
        { GroupName: "d", RoleArn: "role-d" },
      ]),
    ).toEqual({
      groupsToOverride: ["a", "b", "c", "d"],
      iamRolesToOverride: ["role-a", "role-b", "role-d"],
      preferredRole: "role-b",
    });
  });

  it("sets no preferred role when equal precedence groups have different roles", () => {
    expect(
      groupConfigurationFor([
        { GroupName: "a", RoleArn: "role-a", Precedence: 1 },
        { GroupName: "b", RoleArn: "role-b", Precedence: 1 },
      ]).preferredRole,
    ).toBeNull();
    expect(
      groupConfigurationFor([
        { GroupName: "a", RoleArn: "role-x", Precedence: 1 },
        { GroupName: "b", RoleArn: "role-x", Precedence: 1 },
      ]).preferredRole,
    ).toBe("role-x");
  });
});

describe("applyPreTokenGenerationResponse", () => {
  describe("version 1", () => {
    it("changes only the ID token claims", () => {
      const result = applyPreTokenGenerationResponse(
        "1",
        {
          claimsOverrideDetails: {
            claimsToAddOrOverride: {
              tenant: "t1",
              email: "other@example.test",
            },
            claimsToSuppress: ["email_verified"],
          },
        },
        tokens(),
        CLIENT_ID,
      );
      expect(result.idToken).toMatchObject({
        tenant: "t1",
        email: "other@example.test",
      });
      expect(result.idToken).not.toHaveProperty("email_verified");
      expect(result.accessToken).toEqual(tokens().accessToken);
    });

    it("ignores a version 2 response", () => {
      const result = applyPreTokenGenerationResponse(
        "1",
        {
          claimsAndScopeOverrideDetails: {
            idTokenGeneration: { claimsToAddOrOverride: { tenant: "t1" } },
          },
        },
        tokens(),
        CLIENT_ID,
      );
      expect(result).toEqual(tokens());
    });

    it("replaces the groups of both tokens and the roles of the ID token", () => {
      const result = applyPreTokenGenerationResponse(
        "1",
        {
          claimsOverrideDetails: {
            groupOverrideDetails: {
              groupsToOverride: ["writers"],
              iamRolesToOverride: ["role-w"],
              preferredRole: "role-w",
            },
          },
        },
        tokens(),
        CLIENT_ID,
      );
      expect(result.idToken).toMatchObject({
        "cognito:groups": ["writers"],
        "cognito:roles": ["role-w"],
        "cognito:preferred_role": "role-w",
      });
      expect(result.accessToken["cognito:groups"]).toEqual(["writers"]);
    });

    it("suppresses the groups when groupOverrideDetails is null or empty", () => {
      for (const groupOverrideDetails of [null, {}]) {
        const result = applyPreTokenGenerationResponse(
          "1",
          { claimsOverrideDetails: { groupOverrideDetails } },
          tokens(),
          CLIENT_ID,
        );
        expect(result.idToken).not.toHaveProperty("cognito:groups");
        expect(result.idToken).not.toHaveProperty("cognito:roles");
        expect(result.idToken).not.toHaveProperty("cognito:preferred_role");
        expect(result.accessToken).not.toHaveProperty("cognito:groups");
      }
    });

    it("keeps the groups when groupOverrideDetails is absent", () => {
      const result = applyPreTokenGenerationResponse(
        "1",
        { claimsOverrideDetails: { claimsToAddOrOverride: { a: "b" } } },
        tokens(),
        CLIENT_ID,
      );
      expect(result.idToken?.["cognito:groups"]).toEqual(["readers"]);
      expect(result.accessToken["cognito:groups"]).toEqual(["readers"]);
    });
  });

  describe("version 2", () => {
    it("customizes the ID token, the access token and the scopes", () => {
      const result = applyPreTokenGenerationResponse(
        "2",
        {
          claimsAndScopeOverrideDetails: {
            idTokenGeneration: {
              claimsToAddOrOverride: { family_name: "Doe", tags: ["a", 1] },
              claimsToSuppress: ["email"],
            },
            accessTokenGeneration: {
              claimsToAddOrOverride: { tenant: { id: "t1" } },
              claimsToSuppress: ["username"],
              scopesToAdd: ["example.test/read", "has space", "openid"],
              scopesToSuppress: ["aws.cognito.signin.user.admin"],
            },
          },
        },
        tokens(),
        CLIENT_ID,
      );
      expect(result.idToken).toMatchObject({
        family_name: "Doe",
        tags: ["a", 1],
      });
      expect(result.idToken).not.toHaveProperty("email");
      expect(result.accessToken).toMatchObject({
        tenant: { id: "t1" },
        username: "jane",
        scope: "openid email example.test/read",
      });
      expect(result.idToken).not.toHaveProperty("tenant");
    });

    it("drops the scope claim when every scope is suppressed", () => {
      const result = applyPreTokenGenerationResponse(
        "2",
        {
          claimsAndScopeOverrideDetails: {
            accessTokenGeneration: {
              scopesToSuppress: [
                "openid",
                "email",
                "aws.cognito.signin.user.admin",
              ],
            },
          },
        },
        tokens(),
        CLIENT_ID,
      );
      expect(result.accessToken).not.toHaveProperty("scope");
    });

    it("applies groupOverrideDetails to both tokens", () => {
      const result = applyPreTokenGenerationResponse(
        "2",
        {
          claimsAndScopeOverrideDetails: {
            groupOverrideDetails: { groupsToOverride: ["g1", "g2"] },
          },
        },
        tokens(),
        CLIENT_ID,
      );
      expect(result.idToken?.["cognito:groups"]).toEqual(["g1", "g2"]);
      expect(result.idToken).not.toHaveProperty("cognito:roles");
      expect(result.accessToken["cognito:groups"]).toEqual(["g1", "g2"]);
    });

    it("suppresses the groups and the role claims with cognito:groups", () => {
      const result = applyPreTokenGenerationResponse(
        "2",
        {
          claimsAndScopeOverrideDetails: {
            idTokenGeneration: { claimsToSuppress: ["cognito:groups"] },
            accessTokenGeneration: { claimsToSuppress: ["cognito:groups"] },
          },
        },
        tokens(),
        CLIENT_ID,
      );
      expect(result.idToken).not.toHaveProperty("cognito:groups");
      expect(result.idToken).not.toHaveProperty("cognito:roles");
      expect(result.idToken).not.toHaveProperty("cognito:preferred_role");
      expect(result.accessToken).not.toHaveProperty("cognito:groups");
    });

    it("accepts an access token aud only when it is the client id", () => {
      const add = (aud: string) =>
        applyPreTokenGenerationResponse(
          "2",
          {
            claimsAndScopeOverrideDetails: {
              accessTokenGeneration: { claimsToAddOrOverride: { aud } },
              idTokenGeneration: { claimsToAddOrOverride: { aud } },
            },
          },
          tokens(),
          CLIENT_ID,
        );
      expect(add(CLIENT_ID).accessToken.aud).toBe(CLIENT_ID);
      expect(add(CLIENT_ID).idToken).not.toHaveProperty("aud");
      expect(add("other").accessToken).not.toHaveProperty("aud");
    });

    it("refuses complex values for scalar ID token claims", () => {
      const result = applyPreTokenGenerationResponse(
        "2",
        {
          claimsAndScopeOverrideDetails: {
            idTokenGeneration: {
              claimsToAddOrOverride: {
                email_verified: { yes: true },
                address: "1 Example Road",
              },
            },
          },
        },
        tokens(),
        CLIENT_ID,
      );
      expect(result.idToken?.email_verified).toBe(true);
      expect(result.idToken?.address).toBe("1 Example Road");
    });

    it.each([
      "sub",
      "username",
      "client_id",
      "event_id",
      "version",
      "token_use",
      "cognito:username",
      "cognito:groups",
      "cognito:anything",
      "dev:internal",
    ])("cannot add or override %s", (claim) => {
      const result = applyPreTokenGenerationResponse(
        "2",
        {
          claimsAndScopeOverrideDetails: {
            idTokenGeneration: { claimsToAddOrOverride: { [claim]: "x" } },
            accessTokenGeneration: { claimsToAddOrOverride: { [claim]: "x" } },
          },
        },
        tokens(),
        CLIENT_ID,
      );
      expect(result.idToken?.[claim]).not.toBe("x");
      expect(result.accessToken[claim]).not.toBe("x");
    });

    it.each(["sub", "cognito:username", "token_use", "identities"])(
      "cannot suppress %s",
      (claim) => {
        const result = applyPreTokenGenerationResponse(
          "2",
          {
            claimsAndScopeOverrideDetails: {
              idTokenGeneration: { claimsToSuppress: [claim] },
            },
          },
          tokens(),
          CLIENT_ID,
        );
        expect(result.idToken).toEqual(tokens().idToken);
      },
    );

    it("changes the access token scope only through scopesToAdd", () => {
      const result = applyPreTokenGenerationResponse(
        "2",
        {
          claimsAndScopeOverrideDetails: {
            accessTokenGeneration: {
              claimsToAddOrOverride: { scope: "x" },
              claimsToSuppress: ["scope"],
            },
          },
        },
        tokens(),
        CLIENT_ID,
      );
      expect(result.accessToken.scope).toBe(tokens().accessToken.scope);
    });

    it("can suppress a dev: attribute", () => {
      const result = applyPreTokenGenerationResponse(
        "2",
        {
          claimsAndScopeOverrideDetails: {
            idTokenGeneration: { claimsToSuppress: ["dev:internal"] },
          },
        },
        tokens(),
        CLIENT_ID,
      );
      expect(result.idToken).not.toHaveProperty("dev:internal");
    });

    it("customizes an access token without an ID token", () => {
      const result = applyPreTokenGenerationResponse(
        "3",
        {
          claimsAndScopeOverrideDetails: {
            accessTokenGeneration: {
              claimsToAddOrOverride: { tenant: "t1" },
              scopesToAdd: ["example.test/write"],
            },
            groupOverrideDetails: { groupsToOverride: ["ignored"] },
          },
        },
        { accessToken: { sub: CLIENT_ID, scope: "example.test/read" } },
        CLIENT_ID,
      );
      expect(result.idToken).toBeUndefined();
      expect(result.accessToken).toEqual({
        sub: CLIENT_ID,
        scope: "example.test/read example.test/write",
        tenant: "t1",
      });
    });

    it("leaves the tokens unchanged for a null response", () => {
      expect(
        applyPreTokenGenerationResponse(
          "2",
          { claimsAndScopeOverrideDetails: null },
          tokens(),
          CLIENT_ID,
        ),
      ).toEqual(tokens());
    });
  });
});
