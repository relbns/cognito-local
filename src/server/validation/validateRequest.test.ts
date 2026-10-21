import { describe, expect, it } from "vitest";
import { InvalidParameterError } from "../../errors";
import { Targets } from "../../targets/targets";
import { SHAPES } from "./cognitoIdpModel.generated";
import {
  hasInputModel,
  SerializationError,
  validateRequest,
} from "./validateRequest";

const POOL = "local_1uCTiTms";
const CLIENT = "6m3frcb0bh8ad1v8l71dmhkhb0";

const errorOf = (operation: string, input: unknown) => {
  try {
    validateRequest(operation, input);
  } catch (e) {
    return e;
  }
  return undefined;
};

const messageOf = (operation: string, input: unknown) =>
  (errorOf(operation, input) as Error | undefined)?.message;

describe("validateRequest", () => {
  it("accepts a valid request and ignores members the model does not have", () => {
    expect(
      errorOf("InitiateAuth", {
        AuthFlow: "USER_PASSWORD_AUTH",
        ClientId: CLIENT,
        AuthParameters: { USERNAME: "jane", PASSWORD: "Passw0rd!" },
        Extra: { anything: true },
      }),
    ).toBeUndefined();
  });

  it("reports a missing required member", () => {
    const error = errorOf("InitiateAuth", { AuthFlow: "USER_PASSWORD_AUTH" });

    expect(error).toBeInstanceOf(InvalidParameterError);
    expect(error).toMatchObject({
      code: "InvalidParameterException",
      message:
        "1 validation error detected: Value null at 'clientId' failed to satisfy constraint: Member must not be null",
    });
  });

  it("treats a null member and a missing body as absent", () => {
    expect(messageOf("GetUser", { AccessToken: null })).toEqual(
      "1 validation error detected: Value null at 'accessToken' failed to satisfy constraint: Member must not be null",
    );
    expect(messageOf("InitiateAuth", undefined)).toEqual(
      "2 validation errors detected: Value null at 'authFlow' failed to satisfy constraint: Member must not be null; Value null at 'clientId' failed to satisfy constraint: Member must not be null",
    );
  });

  it("lists the enum values for a value outside the set", () => {
    expect(
      messageOf("InitiateAuth", { AuthFlow: "PLAIN", ClientId: CLIENT }),
    ).toEqual(
      "1 validation error detected: Value 'PLAIN' at 'authFlow' failed to satisfy constraint: Member must satisfy enum value set: [USER_SRP_AUTH, REFRESH_TOKEN_AUTH, REFRESH_TOKEN, CUSTOM_AUTH, ADMIN_NO_SRP_AUTH, USER_PASSWORD_AUTH, ADMIN_USER_PASSWORD_AUTH, USER_AUTH]",
    );
  });

  it("reports the pattern and the length of an empty value", () => {
    expect(
      messageOf("AdminGetUser", { UserPoolId: "", Username: "jane" }),
    ).toEqual(
      "2 validation errors detected: Value '' at 'userPoolId' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w-]+_[0-9a-zA-Z]+; Value '' at 'userPoolId' failed to satisfy constraint: Member must have length greater than or equal to 1",
    );
  });

  it("leaves out the value of a sensitive member", () => {
    expect(
      messageOf("InitiateAuth", {
        AuthFlow: "USER_PASSWORD_AUTH",
        ClientId: "not a client",
      }),
    ).toEqual(
      "1 validation error detected: Value at 'clientId' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w+]+",
    );
  });

  it("checks the range of a number", () => {
    expect(messageOf("ListUsers", { UserPoolId: POOL, Limit: 100 })).toEqual(
      "1 validation error detected: Value '100' at 'limit' failed to satisfy constraint: Member must have value less than or equal to 60",
    );
    expect(messageOf("ListUserPools", { MaxResults: 0 })).toEqual(
      "1 validation error detected: Value '0' at 'maxResults' failed to satisfy constraint: Member must have value greater than or equal to 1",
    );
  });

  it("names a nested member by its one-based list position", () => {
    expect(
      messageOf("AdminCreateUser", {
        UserPoolId: POOL,
        Username: "jane",
        UserAttributes: [{ Name: "email", Value: "jane@example.com" }, {}],
      }),
    ).toEqual(
      "1 validation error detected: Value null at 'userAttributes.2.member.name' failed to satisfy constraint: Member must not be null",
    );
  });

  it("reports the items of a list of values together", () => {
    expect(
      messageOf("AdminCreateUser", {
        UserPoolId: POOL,
        Username: "jane",
        DesiredDeliveryMediums: ["EMAIL", "FAX"],
      }),
    ).toEqual(
      "1 validation error detected: Value '[EMAIL, FAX]' at 'desiredDeliveryMediums' failed to satisfy constraint: Member must satisfy constraint: [Member must satisfy enum value set: [SMS, EMAIL]]",
    );
  });

  it("reports map keys and map values", () => {
    expect(
      messageOf("TagResource", {
        ResourceArn: `arn:aws:cognito-idp:us-east-1:123456789012:userpool/${POOL}`,
        Tags: { "": "x".repeat(257) },
      }),
    ).toEqual(
      `2 validation errors detected: Value '{=${"x".repeat(257)}}' at 'tags' failed to satisfy constraint: Map keys must satisfy constraint: [Member must have length greater than or equal to 1]; Value '{=${"x".repeat(257)}}' at 'tags' failed to satisfy constraint: Map value must satisfy constraint: [Member must have length less than or equal to 256]`,
    );
  });

  it("counts every violation in the summary", () => {
    expect(
      messageOf("AdminSetUserPassword", {
        UserPoolId: "pool",
        Username: "",
        Password: "has space",
      }),
    ).toEqual(
      "4 validation errors detected: Value 'pool' at 'userPoolId' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w-]+_[0-9a-zA-Z]+; Value at 'username' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]+; Value at 'username' failed to satisfy constraint: Member must have length greater than or equal to 1; Value at 'password' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\S]+",
    );
  });

  it.each([
    [
      { AuthFlow: "USER_PASSWORD_AUTH", ClientId: 123 },
      "class com.amazon.coral.value.json.numbers.TruncatingBigNumber can not be converted to an String",
    ],
    [
      { AuthFlow: "USER_PASSWORD_AUTH", ClientId: CLIENT, AuthParameters: "x" },
      "Unexpected value type in payload",
    ],
    [
      { AuthFlow: "USER_PASSWORD_AUTH", ClientId: { id: CLIENT } },
      "Start of structure or map found where not expected.",
    ],
    [
      { AuthFlow: ["USER_PASSWORD_AUTH"], ClientId: CLIENT },
      "Start of list found where not expected",
    ],
  ])(
    "answers a wrong JSON type with SerializationException (%j)",
    (input, message) => {
      const error = errorOf("InitiateAuth", input);

      expect(error).toBeInstanceOf(SerializationError);
      expect(error).toMatchObject({ code: "SerializationException", message });
    },
  );

  it("answers wrong types in lists and numbers with SerializationException", () => {
    expect(
      errorOf("AdminCreateUser", {
        UserPoolId: POOL,
        Username: "jane",
        UserAttributes: "email",
      }),
    ).toMatchObject({
      code: "SerializationException",
      message: "Unrecognized collection type class java.lang.String",
    });
    expect(
      errorOf("ListUsers", { UserPoolId: POOL, Limit: "10" }),
    ).toMatchObject({
      code: "SerializationException",
      message: "class java.lang.String can not be converted to an Integer",
    });
    expect(
      errorOf("AdminSetUserPassword", {
        UserPoolId: POOL,
        Username: "jane",
        Password: "Passw0rd!",
        Permanent: "true",
      }),
    ).toMatchObject({
      code: "SerializationException",
      message: "class java.lang.String can not be converted to an Boolean",
    });
  });

  it("does nothing for an operation without an input model", () => {
    expect(errorOf("NoSuchOperation", { anything: 1 })).toBeUndefined();
  });

  it("has an input model for every supported target", () => {
    expect(Object.keys(Targets).filter((t) => !hasInputModel(t))).toEqual([]);
  });

  it("compiles every pattern in the model", () => {
    const patterns = Object.values(SHAPES).flatMap((s) =>
      s.type === "string" && s.pattern !== undefined ? [s.pattern] : [],
    );
    expect(patterns.length).toBeGreaterThan(30);
    for (const pattern of patterns) {
      const dotAll = pattern.startsWith("(?s)");
      expect(
        () =>
          new RegExp(
            `^(?:${dotAll ? pattern.slice(4) : pattern})$`,
            dotAll ? "us" : "u",
          ),
      ).not.toThrow();
    }
  });
});
