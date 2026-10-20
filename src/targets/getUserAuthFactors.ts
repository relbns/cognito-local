import type { Services } from "../services";
import type { Target } from "./Target";

interface GetUserAuthFactorsRequest {
  AccessToken: string;
}

interface GetUserAuthFactorsResponse {
  Username?: string;
  PreferredMfaSetting?: string;
  UserMFASettingList?: string[];
  ConfiguredUserAuthFactors?: string[];
}

export type GetUserAuthFactorsTarget = Target<
  GetUserAuthFactorsRequest,
  GetUserAuthFactorsResponse
>;

type GetUserAuthFactorsServices = Pick<Services, "tokenVerifier">;

export const GetUserAuthFactors =
  ({ tokenVerifier }: GetUserAuthFactorsServices): GetUserAuthFactorsTarget =>
  async (ctx, req) => {
    const { user } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    const factors: string[] = ["PASSWORD"];
    if (user.UserMFASettingList) {
      for (const mfa of user.UserMFASettingList) {
        if (mfa === "SMS_MFA") factors.push("SMS");
        if (mfa === "SOFTWARE_TOKEN_MFA") factors.push("TOTP");
      }
    }

    return {
      Username: user.Username,
      PreferredMfaSetting: user.PreferredMfaSetting,
      UserMFASettingList: user.UserMFASettingList,
      ConfiguredUserAuthFactors: factors,
    };
  };
