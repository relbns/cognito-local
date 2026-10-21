import type {
  AssociateSoftwareTokenRequest,
  AssociateSoftwareTokenResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { InvalidParameterError } from "../errors";
import type { Services } from "../services";
import { newTotpSecret } from "../services/mfaSetup";
import { advanceSignInSession, pendingSignInSession } from "../services/signIn";
import type { Target } from "./Target";

export type AssociateSoftwareTokenTarget = Target<
  AssociateSoftwareTokenRequest,
  AssociateSoftwareTokenResponse
>;

type AssociateSoftwareTokenServices = Pick<
  Services,
  "authSessions" | "cognito" | "tokenVerifier"
>;

export const AssociateSoftwareToken =
  ({
    authSessions,
    cognito,
    tokenVerifier,
  }: AssociateSoftwareTokenServices): AssociateSoftwareTokenTarget =>
  async (ctx, req) => {
    if (!req.AccessToken && !req.Session) {
      throw new InvalidParameterError(
        "Either AccessToken or Session is required",
      );
    }

    if (!req.AccessToken && req.Session) {
      // MFA_SETUP: the secret stays with the sign-in session until VerifySoftwareToken checks a code.
      const session = pendingSignInSession(
        authSessions,
        req.Session,
        "MFA_SETUP",
      );
      const client = await cognito.getAppClient(ctx, session.clientId);
      const secret = newTotpSecret();
      return {
        SecretCode: secret,
        Session: advanceSignInSession(
          authSessions,
          req.Session,
          session,
          { totpSecret: secret, totpVerified: false },
          client?.AuthSessionValidity,
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

    const secret = newTotpSecret();
    await userPool.saveUser(ctx, {
      ...user,
      SoftwareTokenMfaConfiguration: {
        Secret: secret,
        Verified: false,
      },
    });

    return {
      SecretCode: secret,
    };
  };
