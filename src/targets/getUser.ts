import type {
  GetUserRequest,
  GetUserResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import type { Target } from "./Target";

export type GetUserTarget = Target<GetUserRequest, GetUserResponse>;

export const GetUser =
  ({ tokenVerifier }: Pick<Services, "tokenVerifier">): GetUserTarget =>
  async (ctx, req) => {
    const { user } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    return {
      MFAOptions: user.MFAOptions,
      PreferredMfaSetting: user.PreferredMfaSetting,
      UserAttributes: user.Attributes,
      UserMFASettingList: user.UserMFASettingList,
      Username: user.Username,
    };
  };
