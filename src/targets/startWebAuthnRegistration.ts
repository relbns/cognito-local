import * as crypto from "node:crypto";
import type { Services } from "../services";
import type { Target } from "./Target";

interface StartWebAuthnRegistrationRequest {
  AccessToken: string;
}
interface StartWebAuthnRegistrationResponse {
  CredentialCreationOptions?: any;
}

export type StartWebAuthnRegistrationTarget = Target<
  StartWebAuthnRegistrationRequest,
  StartWebAuthnRegistrationResponse
>;

export const StartWebAuthnRegistration =
  ({
    tokenVerifier,
  }: Pick<Services, "tokenVerifier">): StartWebAuthnRegistrationTarget =>
  async (ctx, req) => {
    const { user } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    return {
      CredentialCreationOptions: {
        publicKey: {
          rp: { id: "localhost", name: "cognito-local" },
          user: {
            id: user.Username,
            name: user.Username,
            displayName: user.Username,
          },
          challenge: crypto.randomBytes(32).toString("base64url"),
          pubKeyCredParams: [{ alg: -7, type: "public-key" }],
        },
      },
    };
  };
