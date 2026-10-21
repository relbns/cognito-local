import { describe, expect, it } from "vitest";
import * as TDB from "../__tests__/testDataBuilder";
import { enabledMfaMethods, isMfaRequired, smsMfaDelivery } from "./mfa";

describe("isMfaRequired", () => {
  const withMfa = TDB.user({ UserMFASettingList: ["SMS_MFA"] });
  const withoutMfa = TDB.user();

  it.each([
    ["ON", withoutMfa, true],
    ["OPTIONAL", withMfa, true],
    ["OPTIONAL", withoutMfa, false],
    ["OFF", withMfa, false],
    [undefined, withMfa, true],
  ] as const)("MfaConfiguration %s", (MfaConfiguration, user, expected) => {
    expect(isMfaRequired({ MfaConfiguration }, user)).toBe(expected);
  });
});

describe("enabledMfaMethods", () => {
  it("lists TOTP only once its registration is verified", () => {
    const user = TDB.user({
      UserMFASettingList: ["SMS_MFA", "SOFTWARE_TOKEN_MFA"],
      SoftwareTokenMfaConfiguration: { Secret: "S", Verified: false },
    });
    expect(enabledMfaMethods(user)).toEqual(["SMS_MFA"]);
  });

  it("treats a legacy SMS MFAOption as SMS_MFA", () => {
    const user = TDB.user({
      MFAOptions: [{ DeliveryMedium: "SMS", AttributeName: "phone_number" }],
    });
    expect(enabledMfaMethods(user)).toEqual(["SMS_MFA"]);
  });
});

describe("smsMfaDelivery", () => {
  it("sends to phone_number", () => {
    const user = TDB.user({
      Attributes: [{ Name: "phone_number", Value: "+15555550100" }],
    });
    expect(smsMfaDelivery(user)).toEqual({
      DeliveryMedium: "SMS",
      AttributeName: "phone_number",
      Destination: "+15555550100",
    });
  });

  it("returns null without a phone number", () => {
    expect(smsMfaDelivery(TDB.user({ Attributes: [] }))).toBeNull();
  });
});
