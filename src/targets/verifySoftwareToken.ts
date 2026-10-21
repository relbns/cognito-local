import type {
  VerifySoftwareTokenRequest,
  VerifySoftwareTokenResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import {
  EnableSoftwareTokenMFAError,
  InvalidParameterError,
  NotAuthorizedError,
} from "../errors";
import type { Services } from "../services";
import { completeTotpSetup } from "../services/mfaSetup";
import { advanceSignInSession, pendingSignInSession } from "../services/signIn";
import { verify } from "../services/totp";
import type { Target } from "./Target";

export type VerifySoftwareTokenTarget = Target<
  VerifySoftwareTokenRequest,
  VerifySoftwareTokenResponse
>;

type VerifySoftwareTokenServices = Pick<
  Services,
  "authSessions" | "clock" | "cognito" | "tokenVerifier"
>;

export const VerifySoftwareToken =
  ({
    authSessions,
    clock,
    cognito,
    tokenVerifier,
  }: VerifySoftwareTokenServices): VerifySoftwareTokenTarget =>
  async (ctx, req) => {
    if (!req.UserCode) {
      throw new InvalidParameterError("Missing required parameter UserCode");
    }
    if (!req.AccessToken && !req.Session) {
      throw new InvalidParameterError(
        "Either AccessToken or Session is required",
      );
    }

    if (!req.AccessToken && req.Session) {
      const session = pendingSignInSession(
        authSessions,
        req.Session,
        "MFA_SETUP",
      );
      const secret = session.signIn?.totpSecret;
      if (!secret) {
        throw new InvalidParameterError(
          "User has not associated a software token",
        );
      }
      const userPool = await cognito.getUserPool(ctx, session.userPoolId);
      const client = await cognito.getAppClient(ctx, session.clientId);
      const user = await userPool.getUserByUsername(ctx, session.username);
      if (!user || !client) {
        throw new NotAuthorizedError("Invalid session for the user.");
      }

      await completeTotpSetup(ctx, {
        userPool,
        user,
        secret,
        code: req.UserCode,
        friendlyDeviceName: req.FriendlyDeviceName,
        clock,
      });

      return {
        Status: "SUCCESS",
        Session: advanceSignInSession(
          authSessions,
          req.Session,
          session,
          { totpVerified: true },
          client.AuthSessionValidity,
        ),
      };
    }

    if (!req.AccessToken) {
      throw new InvalidParameterError("Missing required parameter AccessToken");
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
      throw new EnableSoftwareTokenMFAError();
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
