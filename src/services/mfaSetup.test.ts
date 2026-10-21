import { describe, expect, it } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { CodeMismatchError } from "../errors";
import {
  completeTotpSetup,
  mfaSetupOptions,
  needsMfaSetup,
  newTotpSecret,
  nextMfaStep,
  poolMfaFactors,
  totpUri,
} from "./mfaSetup";
import { generate } from "./totp";

const SMS = { SnsCallerArn: "arn:aws:iam::000000000000:role/sms" };

describe("MFA setup", () => {
  describe("poolMfaFactors", () => {
    it("reads SMS from the SMS configuration and TOTP from its switch", () => {
      expect(poolMfaFactors({ SmsConfiguration: SMS })).toEqual({
        sms: true,
        totp: false,
      });
      expect(
        poolMfaFactors({
          SmsConfiguration: SMS,
          SoftwareTokenMfaConfiguration: { Enabled: true },
        }),
      ).toEqual({ sms: true, totp: true });
      expect(
        poolMfaFactors({ SoftwareTokenMfaConfiguration: { Enabled: false } }),
      ).toEqual({ sms: false, totp: false });
    });

    it("offers TOTP when the pool names no factor", () => {
      expect(poolMfaFactors({ MfaConfiguration: "ON" })).toEqual({
        sms: false,
        totp: true,
      });
    });
  });

  it("lists MFAS_CAN_SETUP with SMS before TOTP", () => {
    expect(
      mfaSetupOptions({
        SmsConfiguration: SMS,
        SoftwareTokenMfaConfiguration: { Enabled: true },
      }),
    ).toEqual(["SMS_MFA", "SOFTWARE_TOKEN_MFA"]);
  });

  describe("nextMfaStep", () => {
    const verifiedTotp = {
      UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
      SoftwareTokenMfaConfiguration: { Secret: "S", Verified: true },
    };

    it("needs nothing when MFA is off or optional without a factor", () => {
      expect(
        nextMfaStep({ MfaConfiguration: "OFF" }, TDB.user(verifiedTotp)),
      ).toEqual({ kind: "none" });
      expect(nextMfaStep({ MfaConfiguration: "OPTIONAL" }, TDB.user())).toEqual(
        {
          kind: "none",
        },
      );
    });

    it("challenges with the preferred or only factor, and lets the user choose between several", () => {
      expect(
        nextMfaStep({ MfaConfiguration: "ON" }, TDB.user(verifiedTotp)),
      ).toEqual({ kind: "challenge", method: "SOFTWARE_TOKEN_MFA" });
      const both = {
        ...verifiedTotp,
        UserMFASettingList: ["SMS_MFA", "SOFTWARE_TOKEN_MFA"],
      };
      expect(nextMfaStep({ MfaConfiguration: "ON" }, TDB.user(both))).toEqual({
        kind: "select",
        methods: ["SMS_MFA", "SOFTWARE_TOKEN_MFA"],
      });
      expect(
        nextMfaStep(
          { MfaConfiguration: "ON" },
          TDB.user({ ...both, PreferredMfaSetting: "SMS_MFA" }),
        ),
      ).toEqual({ kind: "challenge", method: "SMS_MFA" });
    });

    it("asks a user without a factor to set one up when the pool requires MFA", () => {
      const user = TDB.user();
      expect(nextMfaStep({ MfaConfiguration: "ON" }, user)).toEqual({
        kind: "setup",
        options: ["SOFTWARE_TOKEN_MFA"],
      });
      expect(needsMfaSetup({ MfaConfiguration: "ON" }, user)).toBe(true);
      expect(needsMfaSetup({ MfaConfiguration: "OPTIONAL" }, user)).toBe(false);
    });

    it("sends SMS MFA to a phone number when the pool sends SMS", () => {
      const user = TDB.user({
        Attributes: [{ Name: "phone_number", Value: "+15550100" }],
      });
      expect(
        nextMfaStep({ MfaConfiguration: "ON", SmsConfiguration: SMS }, user),
      ).toEqual({ kind: "challenge", method: "SMS_MFA" });
    });

    it("cannot proceed when the pool requires MFA but enables no factor", () => {
      expect(
        nextMfaStep(
          {
            MfaConfiguration: "ON",
            SoftwareTokenMfaConfiguration: { Enabled: false },
          },
          TDB.user(),
        ),
      ).toEqual({ kind: "unavailable" });
    });
  });

  it("builds an otpauth URI for an authenticator app", () => {
    expect(
      totpUri(
        { Id: "local_pool", Name: "Example Pool" },
        { Username: "ann" },
        "ABC",
      ),
    ).toEqual(
      "otpauth://totp/Example%20Pool%3Aann?secret=ABC&issuer=Example%20Pool",
    );
  });

  describe("completeTotpSetup", () => {
    const clock = new ClockFake(new Date("2026-10-21T09:00:00Z"));

    it("refuses a wrong code and stores nothing", async () => {
      const userPool = newMockUserPoolService();
      await expect(
        completeTotpSetup(TestContext, {
          userPool,
          user: TDB.user(),
          secret: newTotpSecret(),
          code: "000000",
          clock,
        }),
      ).rejects.toBeInstanceOf(CodeMismatchError);
      expect(userPool.saveUser).not.toHaveBeenCalled();
    });

    it("registers the verified secret as the user's enabled and preferred factor", async () => {
      const userPool = newMockUserPoolService();
      const secret = newTotpSecret();
      const updated = await completeTotpSetup(TestContext, {
        userPool,
        user: TDB.user({ UserMFASettingList: ["SMS_MFA"] }),
        secret,
        code: generate(secret),
        friendlyDeviceName: "Phone",
        clock,
      });
      expect(updated).toMatchObject({
        SoftwareTokenMfaConfiguration: {
          Secret: secret,
          Verified: true,
          FriendlyDeviceName: "Phone",
        },
        UserMFASettingList: ["SMS_MFA", "SOFTWARE_TOKEN_MFA"],
        PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
        UserLastModifiedDate: clock.get(),
      });
    });
  });
});
