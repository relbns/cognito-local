import type {
  VerifySoftwareTokenRequest,
  VerifySoftwareTokenResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { CodeMismatchError, InvalidParameterError } from "../errors";
import type { Services } from "../services";
import { verify } from "../services/totp";
import type { Target } from "./Target";

export type VerifySoftwareTokenTarget = Target<
  VerifySoftwareTokenRequest,
  VerifySoftwareTokenResponse
>;

type VerifySoftwareTokenServices = Pick<Services, "tokenVerifier">;

export const VerifySoftwareToken =
  ({ tokenVerifier }: VerifySoftwareTokenServices): VerifySoftwareTokenTarget =>
  async (ctx, req) => {
    if (!req.UserCode) {
      throw new InvalidParameterError("Missing required parameter UserCode");
    }
    if (!req.AccessToken && !req.Session) {
      throw new InvalidParameterError(
        "Either AccessToken or Session is required",
      );
    }
    if (!req.AccessToken) {
      throw new InvalidParameterError(
        "VerifySoftwareToken via Session (MFA_SETUP flow) is not supported; call with AccessToken",
      );
    }

    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    const secret = user.SoftwareTokenMfaConfiguration?.Secret;
    if (!secret) {
      throw new InvalidParameterError(
        "User has not associated a software token",
      );
    }

    if (!verify(secret, req.UserCode)) {
      throw new CodeMismatchError();
    }

    const existingMethods = user.UserMFASettingList ?? [];
    const UserMFASettingList = existingMethods.includes("SOFTWARE_TOKEN_MFA")
      ? existingMethods
      : [...existingMethods, "SOFTWARE_TOKEN_MFA"];

    await userPool.saveUser(ctx, {
      ...user,
      SoftwareTokenMfaConfiguration: {
        Secret: secret,
        Verified: true,
        FriendlyDeviceName:
          req.FriendlyDeviceName ??
          user.SoftwareTokenMfaConfiguration?.FriendlyDeviceName,
      },
      UserMFASettingList,
    });

    return {
      Status: "SUCCESS",
      Session: req.Session,
    };
  };
