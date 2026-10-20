import type {
  AssociateSoftwareTokenRequest,
  AssociateSoftwareTokenResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { InvalidParameterError } from "../errors";
import type { Services } from "../services";
import { generateSecret } from "../services/totp";
import type { Target } from "./Target";

export type AssociateSoftwareTokenTarget = Target<
  AssociateSoftwareTokenRequest,
  AssociateSoftwareTokenResponse
>;

type AssociateSoftwareTokenServices = Pick<Services, "tokenVerifier">;

export const AssociateSoftwareToken =
  ({
    tokenVerifier,
  }: AssociateSoftwareTokenServices): AssociateSoftwareTokenTarget =>
  async (ctx, req) => {
    if (!req.AccessToken && !req.Session) {
      throw new InvalidParameterError(
        "Either AccessToken or Session is required",
      );
    }

    if (!req.AccessToken) {
      throw new InvalidParameterError(
        "AssociateSoftwareToken via Session (MFA_SETUP flow) is not supported; call with AccessToken",
      );
    }

    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    const secret = generateSecret();
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
