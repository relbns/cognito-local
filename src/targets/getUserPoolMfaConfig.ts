import type {
  GetUserPoolMfaConfigRequest,
  GetUserPoolMfaConfigResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { webAuthnConfigurationResponse } from "../services/webAuthn";
import type { Target } from "./Target";

export type GetUserPoolMfaConfigTarget = Target<
  GetUserPoolMfaConfigRequest,
  GetUserPoolMfaConfigResponse
>;

type GetUserPoolMfaConfigServices = Pick<Services, "cognito">;

export const GetUserPoolMfaConfig =
  ({ cognito }: GetUserPoolMfaConfigServices): GetUserPoolMfaConfigTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);

    return {
      MfaConfiguration: userPool.options.MfaConfiguration,
      SmsMfaConfiguration: {
        SmsAuthenticationMessage: userPool.options.SmsAuthenticationMessage,
        SmsConfiguration: userPool.options.SmsConfiguration,
      },
      SoftwareTokenMfaConfiguration: {
        Enabled:
          userPool.options.SoftwareTokenMfaConfiguration?.Enabled ?? false,
      },
      WebAuthnConfiguration: webAuthnConfigurationResponse(
        userPool.options.WebAuthnConfiguration,
      ),
    };
  };
