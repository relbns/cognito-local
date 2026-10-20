import { describe, expect, it } from "vitest";
import {
  claimsFromForm,
  federatedUserId,
  type IdentityProviderConfig,
  identitiesClaim,
  mockIdpDefaults,
  providerIssuer,
} from "./federation";

const provider = (
  type: string,
  extra: Partial<IdentityProviderConfig> = {},
): IdentityProviderConfig => ({
  ProviderName: type,
  ProviderType: type,
  ...extra,
});

describe("federatedUserId", () => {
  it.each([
    ["Google", { sub: "g1" }, "g1"],
    ["Facebook", { id: "f1" }, "f1"],
    ["LoginWithAmazon", { user_id: "amzn1.account.X" }, "amzn1.account.X"],
    ["SignInWithApple", { sub: "a1" }, "a1"],
    ["OIDC", { sub: "o1" }, "o1"],
    ["SAML", { NameID: "jane@example.com" }, "jane@example.com"],
  ])("reads the %s subject", (type, claims, expected) => {
    expect(federatedUserId(provider(type), claims)).toBe(expected);
  });

  it("follows the username mapping except for SAML", () => {
    expect(
      federatedUserId(
        provider("OIDC", { AttributeMapping: { username: "oid" } }),
        {
          sub: "s",
          oid: "o",
        },
      ),
    ).toBe("o");
    expect(
      federatedUserId(
        provider("SAML", { AttributeMapping: { username: "x" } }),
        {
          NameID: "n",
          x: "y",
        },
      ),
    ).toBe("n");
  });
});

describe("identitiesClaim", () => {
  it("serializes primary and dateCreated as strings like the ID token does", () => {
    expect(
      identitiesClaim([
        {
          Name: "identities",
          Value: JSON.stringify([
            {
              userId: "1",
              providerName: "Google",
              providerType: "Google",
              issuer: null,
              primary: true,
              dateCreated: 1642699117273,
            },
          ]),
        },
      ]),
    ).toEqual([
      {
        userId: "1",
        providerName: "Google",
        providerType: "Google",
        issuer: null,
        primary: "true",
        dateCreated: "1642699117273",
      },
    ]);
  });

  it("is absent for users without identities", () => {
    expect(
      identitiesClaim([{ Name: "email", Value: "a@b.c" }]),
    ).toBeUndefined();
  });
});

describe("providerIssuer", () => {
  it("reads the SAML entityID from the metadata file", () => {
    expect(
      providerIssuer(
        provider("SAML", {
          ProviderDetails: {
            MetadataFile: '<EntityDescriptor entityID="http://idp.test/x">',
          },
        }),
      ),
    ).toBe("http://idp.test/x");
    expect(providerIssuer(provider("Google"))).toBeNull();
  });
});

describe("mock IdP form", () => {
  it("names the form claims after the attribute mapping", () => {
    const defaults = mockIdpDefaults(
      provider("SAML", {
        AttributeMapping: {
          email:
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        },
      }),
    );
    expect(defaults.subjectClaim).toBe("NameID");
    expect(defaults.fields[0].claim).toBe(
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    );
  });

  it("collects claims and the subject from the posted form", () => {
    expect(
      claimsFromForm(provider("Facebook"), {
        subject: " 101 ",
        claim_name: ["email", "", "name"],
        claim_value: ["a@b.c", "ignored", ""],
      }),
    ).toEqual({ id: "101", email: "a@b.c" });
  });
});
