import { describe, expect, it } from "vitest";
import { InvalidPasswordError } from "../errors";
import {
  AWS_DEFAULT_PASSWORD_POLICY,
  assertPasswordConformsToPolicy,
  normalizePasswordPolicy,
  PASSWORD_SYMBOLS,
  passwordPolicyViolation,
} from "./passwordPolicy";

describe("passwordPolicyViolation", () => {
  it.each([
    ["Aa1!", "Password not long enough"],
    ["aaaaaaa1!", "Password must have uppercase characters"],
    ["AAAAAAA1!", "Password must have lowercase characters"],
    ["Aaaaaaaa!", "Password must have numeric characters"],
    ["Aaaaaaaa1", "Password must have symbol characters"],
  ])("rejects %s under the AWS default policy", (password, expected) => {
    expect(passwordPolicyViolation(password)).toEqual(expected);
  });

  it("accepts a password meeting every default requirement", () => {
    expect(passwordPolicyViolation("Passw0rd!")).toBeNull();
  });

  it.each([...PASSWORD_SYMBOLS])("counts %j as a symbol", (symbol) => {
    expect(passwordPolicyViolation(`Aaaaaaa1${symbol}`)).toBeNull();
  });

  it("does not count other characters as symbols", () => {
    expect(passwordPolicyViolation("Aaaaaaa1€")).toEqual(
      "Password must have symbol characters",
    );
  });

  it("applies only the requirements a custom policy enables", () => {
    expect(
      passwordPolicyViolation("abcdef", {
        MinimumLength: 6,
        RequireUppercase: false,
        RequireLowercase: true,
        RequireNumbers: false,
        RequireSymbols: false,
      }),
    ).toBeNull();
  });
});

describe("normalizePasswordPolicy", () => {
  it("treats unset requirement flags as false and keeps defaults for length and validity", () => {
    expect(normalizePasswordPolicy({ RequireNumbers: true })).toEqual({
      MinimumLength: 8,
      RequireUppercase: false,
      RequireLowercase: false,
      RequireNumbers: true,
      RequireSymbols: false,
      TemporaryPasswordValidityDays: 7,
    });
  });

  it("keeps an absent policy absent", () => {
    expect(normalizePasswordPolicy(undefined)).toBeUndefined();
  });
});

describe("assertPasswordConformsToPolicy", () => {
  const enforced = { PasswordPolicyConfig: { Enforce: true } };

  it("falls back to the AWS default policy when the pool has none", () => {
    expect(() =>
      assertPasswordConformsToPolicy(enforced, { Id: "test" }, "short"),
    ).toThrow(
      new InvalidPasswordError(
        "Password does not conform to policy: Password not long enough",
      ),
    );
  });

  it("uses the SignUp wording for SignUp", () => {
    expect(() =>
      assertPasswordConformsToPolicy(
        enforced,
        { Id: "test" },
        "password1!",
        "signUp",
      ),
    ).toThrow(
      new InvalidPasswordError(
        "Password did not conform with policy: Password must have uppercase characters",
      ),
    );
  });

  it("uses the pool's policy", () => {
    expect(() =>
      assertPasswordConformsToPolicy(
        enforced,
        {
          Id: "test",
          Policies: {
            PasswordPolicy: {
              ...AWS_DEFAULT_PASSWORD_POLICY,
              MinimumLength: 12,
            },
          },
        },
        "Passw0rd!",
      ),
    ).toThrow("Password not long enough");
  });

  it("does nothing when enforcement is turned off in config", () => {
    expect(() =>
      assertPasswordConformsToPolicy(
        { PasswordPolicyConfig: { Enforce: false } },
        { Id: "test" },
        "x",
      ),
    ).not.toThrow();
  });

  it("enforces when no config is given", () => {
    expect(() =>
      assertPasswordConformsToPolicy(undefined, { Id: "test" }, "x"),
    ).toThrow(InvalidPasswordError);
  });
});
