import { describe, expect, it } from "vitest";
import type { IdentityProviderConfig } from "./federation";
import {
  chooserAccounts,
  configuredMockAccounts,
  mockAccountClaims,
  mockIdpView,
  mockSubject,
  nameFromEmail,
} from "./mockIdpAccounts";

const provider = (
  ProviderType: string,
  AttributeMapping?: Record<string, string>,
  ProviderName = ProviderType,
): IdentityProviderConfig => ({
  ProviderName,
  ProviderType,
  AttributeMapping,
});

describe("mockSubject", () => {
  it.each([
    ["Google", /^1\d{20}$/],
    ["Facebook", /^10\d{15}$/],
    ["LoginWithAmazon", /^amzn1\.account\.[A-Z2-7]{28}$/],
    ["SignInWithApple", /^\d{6}\.[0-9a-f]{32}\.\d{4}$/],
    [
      "OIDC",
      /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    ],
  ])("is shaped like a %s id", (type, shape) => {
    expect(mockSubject(provider(type), "jane@example.test")).toMatch(shape);
  });

  it("is the email itself for SAML", () => {
    expect(mockSubject(provider("SAML"), " Jane@Example.test ")).toBe(
      "jane@example.test",
    );
  });

  it("is stable per provider and email, and differs across them", () => {
    const google = provider("Google");
    expect(mockSubject(google, "jane@example.test")).toBe(
      mockSubject(google, " JANE@example.test"),
    );
    expect(mockSubject(google, "jane@example.test")).not.toBe(
      mockSubject(google, "john@example.test"),
    );
    expect(mockSubject(google, "jane@example.test")).not.toBe(
      mockSubject(provider("Google", {}, "Workspace"), "jane@example.test"),
    );
  });
});

describe("nameFromEmail", () => {
  it.each([
    ["jane.doe@example.test", "Jane Doe"],
    ["sam_rivera+test@example.test", "Sam Rivera"],
    ["x@example.test", "X"],
  ])("%s gives %s", (email, name) => {
    expect(nameFromEmail(email)).toBe(name);
  });
});

describe("mockAccountClaims", () => {
  it("returns email, a verified flag, the name split in two and the subject", () => {
    const google = provider("Google");
    expect(
      mockAccountClaims(google, {
        email: "pat@example.test",
        name: "Pat Van Lee",
      }),
    ).toEqual({
      sub: mockSubject(google, "pat@example.test"),
      email: "pat@example.test",
      email_verified: "true",
      name: "Pat Van Lee",
      given_name: "Pat",
      family_name: "Van Lee",
    });
  });

  it("makes a name from the email and has no family name for one word", () => {
    const claims = mockAccountClaims(provider("Google"), {
      email: "pat@example.test",
      name: " ",
    });
    expect(claims.name).toBe("Pat");
    expect(claims.given_name).toBe("Pat");
    expect(claims.family_name).toBeUndefined();
  });

  it("also returns the claims under the names AttributeMapping reads", () => {
    const claims = mockAccountClaims(
      provider("SAML", {
        email: "http://schemas.example.test/claims/emailaddress",
        name: "displayName",
      }),
      { email: "pat@example.test", name: "Pat Lee" },
    );
    expect(claims["http://schemas.example.test/claims/emailaddress"]).toBe(
      "pat@example.test",
    );
    expect(claims.displayName).toBe("Pat Lee");
    expect(claims.NameID).toBe("pat@example.test");
  });

  it("uses the provider's subject claim, the configured sub and configured claims", () => {
    const claims = mockAccountClaims(provider("Facebook"), {
      email: "pat@example.test",
      name: "Pat Lee",
      sub: "10000000000000001",
      claims: { email_verified: "false", locale: "en" },
    });
    expect(claims.id).toBe("10000000000000001");
    expect(claims.sub).toBeUndefined();
    expect(claims.email_verified).toBe("false");
    expect(claims.locale).toBe("en");
  });
});

describe("configured accounts and the view", () => {
  const config = {
    Mode: "mock" as const,
    MockAccounts: [{ email: "all@example.test" }],
    MockView: "developer" as const,
    Providers: {
      Google: {
        MockAccounts: [{ email: "g@example.test", name: "Gail" }],
        MockView: "signin" as const,
      },
    },
  };

  it("takes a provider's own MockAccounts over the global ones", () => {
    expect(
      configuredMockAccounts(config, provider("Google")).map((a) => a.email),
    ).toEqual(["g@example.test"]);
    expect(configuredMockAccounts(config, provider("OIDC"))).toEqual([
      {
        email: "all@example.test",
        name: "All",
        sub: undefined,
        claims: undefined,
        configured: true,
      },
    ]);
    expect(configuredMockAccounts(undefined, provider("OIDC"))).toEqual([]);
  });

  it("picks the view from ?dev, then the provider, then the global setting", () => {
    expect(mockIdpView(config, provider("Google"), undefined)).toBe("signin");
    expect(mockIdpView(config, provider("OIDC"), undefined)).toBe("developer");
    expect(mockIdpView(config, provider("OIDC"), "0")).toBe("signin");
    expect(mockIdpView(undefined, provider("OIDC"), "1")).toBe("developer");
    expect(mockIdpView(undefined, provider("OIDC"), undefined)).toBe("signin");
  });

  it("lists remembered accounts first, without repeating a configured one", () => {
    const remembered = Buffer.from(
      JSON.stringify({
        Google: [
          { e: "new@example.test", n: "New Person" },
          { e: "G@example.test", n: "Stale Name" },
        ],
        OIDC: [{ e: "other@example.test", n: "Other" }],
      }),
    ).toString("base64url");
    const req = {
      headers: {
        cookie: `a=b; cognito_emulator_mock_idp_accounts=${remembered}`,
      },
    } as any;
    expect(
      chooserAccounts(req, config, provider("Google")).map((a) => [
        a.email,
        a.name,
        a.configured,
      ]),
    ).toEqual([
      ["new@example.test", "New Person", false],
      ["g@example.test", "Gail", true],
    ]);
  });
});
