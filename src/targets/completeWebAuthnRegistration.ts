import * as uuid from "uuid";
import type { Services } from "../services";
import type { Target } from "./Target";

interface CompleteWebAuthnRegistrationRequest {
  AccessToken: string;
  Credential?: any;
}
type CompleteWebAuthnRegistrationResponse = {};

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
    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    const credentials = ((user as any)._webauthnCredentials as any[]) ?? [];
    credentials.push({
      CredentialId: uuid.v4(),
      FriendlyCredentialName: req.Credential?.friendlyName,
      RelyingPartyId: "localhost",
      AuthenticatorAttachment: "platform",
      AuthenticatorTransports: ["internal"],
      CreatedAt: clock.get(),
    });

    await userPool.saveUser(ctx, {
      ...user,
      _webauthnCredentials: credentials,
      UserLastModifiedDate: clock.get(),
    } as any);

    return {};
  };
