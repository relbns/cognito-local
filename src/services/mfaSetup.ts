import { CodeMismatchError } from "../errors";
import type { Clock } from "./clock";
import type { Context } from "./context";
import {
  enabledMfaMethods,
  isMfaRequired,
  type MfaMethod,
  smsMfaDelivery,
} from "./mfa";
import { generateSecret, verify as verifyTotp } from "./totp";
import type { User, UserPool, UserPoolService } from "./userPoolService";

export type MfaStep =
  | { kind: "none" }
  | { kind: "unavailable" }
  | { kind: "challenge"; method: MfaMethod }
  | { kind: "select"; methods: readonly MfaMethod[] }
  | { kind: "setup"; options: readonly MfaMethod[] };

type MfaPool = Pick<
  UserPool,
  "MfaConfiguration" | "SmsConfiguration" | "SoftwareTokenMfaConfiguration"
>;

// A pool that requires MFA but names no factor (a bare seed, say) offers TOTP.
export const poolMfaFactors = (
  userPool: MfaPool,
): { sms: boolean; totp: boolean } => {
  const sms = !!userPool.SmsConfiguration;
  const totpSetting = userPool.SoftwareTokenMfaConfiguration?.Enabled;
  return { sms, totp: totpSetting ?? !sms };
};

/** The factors a user can register in an MFA_SETUP challenge, in Cognito's MFAS_CAN_SETUP order. */
export const mfaSetupOptions = (userPool: MfaPool): MfaMethod[] => {
  const factors = poolMfaFactors(userPool);
  return [
    ...(factors.sms ? (["SMS_MFA"] as const) : []),
    ...(factors.totp ? (["SOFTWARE_TOKEN_MFA"] as const) : []),
  ];
};

/** What a user must do after the first factor: nothing, answer MFA, choose a factor, or register one. */
export const nextMfaStep = (userPool: MfaPool, user: User): MfaStep => {
  if (!isMfaRequired(userPool, user)) return { kind: "none" };

  const methods = enabledMfaMethods(user);
  if (methods.length > 0) {
    const preferred = methods.find((m) => m === user.PreferredMfaSetting);
    if (preferred) return { kind: "challenge", method: preferred };
    if (methods.length === 1) return { kind: "challenge", method: methods[0] };
    return { kind: "select", methods };
  }
  if (userPool.MfaConfiguration !== "ON") return { kind: "unavailable" };

  if (poolMfaFactors(userPool).sms && smsMfaDelivery(user)) {
    return { kind: "challenge", method: "SMS_MFA" };
  }
  const options = mfaSetupOptions(userPool);
  return options.length > 0
    ? { kind: "setup", options }
    : { kind: "unavailable" };
};

export const needsMfaSetup = (userPool: MfaPool, user: User): boolean =>
  nextMfaStep(userPool, user).kind === "setup";

export const newTotpSecret = (): string => generateSecret();

export const totpUri = (
  userPool: Pick<UserPool, "Id" | "Name">,
  user: Pick<User, "Username">,
  secret: string,
): string => {
  const issuer = userPool.Name ?? userPool.Id;
  return `otpauth://totp/${encodeURIComponent(`${issuer}:${user.Username}`)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`;
};

/** Checks a code against a new TOTP secret and registers it as the user's enabled, preferred factor. */
export const completeTotpSetup = async (
  ctx: Context,
  {
    userPool,
    user,
    secret,
    code,
    friendlyDeviceName,
    clock,
  }: {
    userPool: UserPoolService;
    user: User;
    secret: string;
    code: string;
    friendlyDeviceName?: string;
    clock: Clock;
  },
): Promise<User> => {
  if (!verifyTotp(secret, code)) {
    throw new CodeMismatchError();
  }
  return userPool.updateUser(ctx, user, (latest) => {
    const methods = latest.UserMFASettingList ?? [];
    return {
      ...latest,
      SoftwareTokenMfaConfiguration: {
        Secret: secret,
        Verified: true,
        FriendlyDeviceName:
          friendlyDeviceName ??
          latest.SoftwareTokenMfaConfiguration?.FriendlyDeviceName,
      },
      UserMFASettingList: methods.includes("SOFTWARE_TOKEN_MFA")
        ? methods
        : [...methods, "SOFTWARE_TOKEN_MFA"],
      PreferredMfaSetting: latest.PreferredMfaSetting ?? "SOFTWARE_TOKEN_MFA",
      UserLastModifiedDate: clock.get(),
    };
  });
};
