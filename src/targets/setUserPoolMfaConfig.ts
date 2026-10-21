import type {
  SetUserPoolMfaConfigRequest,
  SetUserPoolMfaConfigResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { webAuthnConfigurationResponse } from "../services/webAuthn";
import type { Target } from "./Target";

export type SetUserPoolMfaConfigTarget = Target<
  SetUserPoolMfaConfigRequest,
  SetUserPoolMfaConfigResponse
>;

type SetUserPoolMfaConfigServices = Pick<Services, "cognito" | "clock">;

export const SetUserPoolMfaConfig =
  ({
    cognito,
    clock,
  }: SetUserPoolMfaConfigServices): SetUserPoolMfaConfigTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);

    await userPool.updateOptions(ctx, {
      ...userPool.options,
      MfaConfiguration:
        req.MfaConfiguration ?? userPool.options.MfaConfiguration,
      SmsAuthenticationMessage:
        req.SmsMfaConfiguration?.SmsAuthenticationMessage ??
        userPool.options.SmsAuthenticationMessage,
      SmsConfiguration:
        req.SmsMfaConfiguration?.SmsConfiguration ??
        userPool.options.SmsConfiguration,
      SoftwareTokenMfaConfiguration: req.SoftwareTokenMfaConfiguration
        ? {
            Enabled: req.SoftwareTokenMfaConfiguration.Enabled ?? false,
          }
        : userPool.options.SoftwareTokenMfaConfiguration,
      WebAuthnConfiguration:
        req.WebAuthnConfiguration ?? userPool.options.WebAuthnConfiguration,
      LastModifiedDate: clock.get(),
    });

    return {
      MfaConfiguration:
        req.MfaConfiguration ?? userPool.options.MfaConfiguration,
      SmsMfaConfiguration: {
        SmsAuthenticationMessage:
          req.SmsMfaConfiguration?.SmsAuthenticationMessage ??
          userPool.options.SmsAuthenticationMessage,
        SmsConfiguration:
          req.SmsMfaConfiguration?.SmsConfiguration ??
          userPool.options.SmsConfiguration,
      },
      SoftwareTokenMfaConfiguration: {
        Enabled:
          req.SoftwareTokenMfaConfiguration?.Enabled ??
          userPool.options.SoftwareTokenMfaConfiguration?.Enabled ??
          false,
      },
      WebAuthnConfiguration: webAuthnConfigurationResponse(
        req.WebAuthnConfiguration ?? userPool.options.WebAuthnConfiguration,
      ),
    };
  };
