import type {
  GetUserRequest,
  GetUserResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { readableAttributes } from "../services/appClient";
import type { Target } from "./Target";

export type GetUserTarget = Target<GetUserRequest, GetUserResponse>;

export const GetUser =
  ({
    cognito,
    tokenVerifier,
  }: Pick<Services, "cognito" | "tokenVerifier">): GetUserTarget =>
  async (ctx, req) => {
    const { user, claims } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );
    const client = claims.client_id
      ? await cognito.getAppClient(ctx, claims.client_id)
      : null;

    return {
      MFAOptions: user.MFAOptions,
      PreferredMfaSetting: user.PreferredMfaSetting,
      UserAttributes: readableAttributes(client, user.Attributes),
      UserMFASettingList: user.UserMFASettingList,
      Username: user.Username,
    };
  };
