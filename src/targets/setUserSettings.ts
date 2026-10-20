import type {
  SetUserSettingsRequest,
  SetUserSettingsResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import type { Target } from "./Target";

export type SetUserSettingsTarget = Target<
  SetUserSettingsRequest,
  SetUserSettingsResponse
>;

type SetUserSettingsServices = Pick<Services, "clock" | "tokenVerifier">;

export const SetUserSettings =
  ({ clock, tokenVerifier }: SetUserSettingsServices): SetUserSettingsTarget =>
  async (ctx, req) => {
    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    const mfaSettingList: string[] = [];

    if (req.MFAOptions) {
      for (const opt of req.MFAOptions) {
        if (opt.DeliveryMedium === "SMS") {
          mfaSettingList.push("SMS_MFA");
        }
      }
    }

    await userPool.saveUser(ctx, {
      ...user,
      MFAOptions: req.MFAOptions as any,
      UserMFASettingList: mfaSettingList,
      UserLastModifiedDate: clock.get(),
    });

    return {};
  };
