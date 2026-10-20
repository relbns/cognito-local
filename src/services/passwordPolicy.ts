import type { PasswordPolicyType } from "@aws-sdk/client-cognito-identity-provider";
import { InvalidPasswordError } from "../errors";
import type { Config } from "../server/config";
import type { UserPool } from "./userPoolService";

export const AWS_DEFAULT_PASSWORD_POLICY: Required<
  Pick<
    PasswordPolicyType,
    | "MinimumLength"
    | "RequireUppercase"
    | "RequireLowercase"
    | "RequireNumbers"
    | "RequireSymbols"
    | "TemporaryPasswordValidityDays"
  >
> = {
  MinimumLength: 8,
  RequireUppercase: true,
  RequireLowercase: true,
  RequireNumbers: true,
  RequireSymbols: true,
  TemporaryPasswordValidityDays: 7,
};

export const PASSWORD_SYMBOLS = "^$*.[]{}()?\"!@#%&/\\,><':;|_~`=+- ";

export type PasswordPolicyMessageStyle = "signUp" | "default";

const MESSAGE_PREFIX: Record<PasswordPolicyMessageStyle, string> = {
  signUp: "Password did not conform with policy",
  default: "Password does not conform to policy",
};

// A PasswordPolicy given in a request replaces the default: unset flags are false, as in AWS.
export const normalizePasswordPolicy = (
  policy: PasswordPolicyType | undefined,
): PasswordPolicyType | undefined =>
  policy
    ? {
        ...policy,
        MinimumLength:
          policy.MinimumLength ?? AWS_DEFAULT_PASSWORD_POLICY.MinimumLength,
        RequireUppercase: policy.RequireUppercase ?? false,
        RequireLowercase: policy.RequireLowercase ?? false,
        RequireNumbers: policy.RequireNumbers ?? false,
        RequireSymbols: policy.RequireSymbols ?? false,
        TemporaryPasswordValidityDays:
          policy.TemporaryPasswordValidityDays ??
          AWS_DEFAULT_PASSWORD_POLICY.TemporaryPasswordValidityDays,
      }
    : undefined;

export const passwordPolicyViolation = (
  password: string,
  policy: PasswordPolicyType = AWS_DEFAULT_PASSWORD_POLICY,
): string | null => {
  if (password.length < (policy.MinimumLength ?? 0)) {
    return "Password not long enough";
  }
  if (policy.RequireUppercase && !/[A-Z]/.test(password)) {
    return "Password must have uppercase characters";
  }
  if (policy.RequireLowercase && !/[a-z]/.test(password)) {
    return "Password must have lowercase characters";
  }
  if (policy.RequireNumbers && !/[0-9]/.test(password)) {
    return "Password must have numeric characters";
  }
  if (
    policy.RequireSymbols &&
    ![...password].some((c) => PASSWORD_SYMBOLS.includes(c))
  ) {
    return "Password must have symbol characters";
  }
  return null;
};

export const assertPasswordConformsToPolicy = (
  config: Pick<Config, "PasswordPolicyConfig"> | undefined,
  userPool: UserPool,
  password: string,
  style: PasswordPolicyMessageStyle = "default",
): void => {
  if (config?.PasswordPolicyConfig?.Enforce === false) {
    return;
  }
  const violation = passwordPolicyViolation(
    password,
    userPool.Policies?.PasswordPolicy ?? AWS_DEFAULT_PASSWORD_POLICY,
  );
  if (violation) {
    throw new InvalidPasswordError(`${MESSAGE_PREFIX[style]}: ${violation}`);
  }
};
