import type {
  SetUserMFAPreferenceRequest,
  SetUserMFAPreferenceResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { InvalidParameterError } from "../errors";
import type { Services } from "../services";
import { passkeyMfaPreference } from "../services/passkeys";
import type { Target } from "./Target";

export type SetUserMFAPreferenceTarget = Target<
  SetUserMFAPreferenceRequest,
  SetUserMFAPreferenceResponse
>;

type SetUserMFAPreferenceServices = Pick<Services, "tokenVerifier">;

export const SetUserMFAPreference =
  ({
    tokenVerifier,
  }: SetUserMFAPreferenceServices): SetUserMFAPreferenceTarget =>
  async (ctx, req) => {
    if (!req.AccessToken) {
      throw new InvalidParameterError("Missing required parameter AccessToken");
    }

    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    const sms = req.SMSMfaSettings;
    const software = req.SoftwareTokenMfaSettings;

    if (software?.Enabled && !user.SoftwareTokenMfaConfiguration?.Verified) {
      throw new InvalidParameterError(
        "User has not verified software token MFA",
      );
    }

    const methods = new Set(user.UserMFASettingList ?? []);
    if (sms) {
      if (sms.Enabled) methods.add("SMS_MFA");
      else methods.delete("SMS_MFA");
    }
    if (software) {
      if (software.Enabled) methods.add("SOFTWARE_TOKEN_MFA");
      else methods.delete("SOFTWARE_TOKEN_MFA");
    }

    const preferred = sms?.PreferredMfa
      ? "SMS_MFA"
      : software?.PreferredMfa
        ? "SOFTWARE_TOKEN_MFA"
        : undefined;

    if (preferred && !methods.has(preferred)) {
      throw new InvalidParameterError(
        `Cannot set ${preferred} as preferred — it is not enabled`,
      );
    }

    const webAuthnMfa = passkeyMfaPreference(
      userPool.options,
      req.WebAuthnMfaSettings,
      user.WebAuthnMfaEnabled,
      [...methods],
    );

    await userPool.saveUser(ctx, {
      ...user,
      UserMFASettingList: [...methods],
      PreferredMfaSetting: preferred,
      WebAuthnMfaEnabled: webAuthnMfa,
    });

    return {};
  };
