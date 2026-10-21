import type {
  CompleteWebAuthnRegistrationRequest,
  CompleteWebAuthnRegistrationResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { completePasskeyRegistration } from "../services/passkeys";
import type { Target } from "./Target";

export type CompleteWebAuthnRegistrationTarget = Target<
  CompleteWebAuthnRegistrationRequest,
  CompleteWebAuthnRegistrationResponse
>;

export const CompleteWebAuthnRegistration =
  ({
    clock,
    tokenVerifier,
  }: Pick<
    Services,
    "clock" | "tokenVerifier"
  >): CompleteWebAuthnRegistrationTarget =>
  async (ctx, req) => {
    const { claims, user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    await completePasskeyRegistration(ctx, {
      userPool,
      user,
      clientId: claims.client_id,
      credential: req.Credential,
      clock,
    });

    return {};
  };
