import type {
  StartWebAuthnRegistrationRequest,
  StartWebAuthnRegistrationResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { startPasskeyRegistration } from "../services/passkeys";
import type { Target } from "./Target";

export type StartWebAuthnRegistrationTarget = Target<
  StartWebAuthnRegistrationRequest,
  StartWebAuthnRegistrationResponse
>;

export const StartWebAuthnRegistration =
  ({
    clock,
    tokenVerifier,
  }: Pick<
    Services,
    "clock" | "tokenVerifier"
  >): StartWebAuthnRegistrationTarget =>
  async (ctx, req) => {
    const { claims, user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    return {
      CredentialCreationOptions: await startPasskeyRegistration(ctx, {
        userPool,
        user,
        clientId: claims.client_id,
        clock,
      }),
    };
  };
