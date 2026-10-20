import { ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
import type { Target } from "./Target";

interface DeleteWebAuthnCredentialRequest {
  AccessToken: string;
  CredentialId: string;
}
type DeleteWebAuthnCredentialResponse = {};

export type DeleteWebAuthnCredentialTarget = Target<
  DeleteWebAuthnCredentialRequest,
  DeleteWebAuthnCredentialResponse
>;

export const DeleteWebAuthnCredential =
  ({
    clock,
    tokenVerifier,
  }: Pick<
    Services,
    "clock" | "tokenVerifier"
  >): DeleteWebAuthnCredentialTarget =>
  async (ctx, req) => {
    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    const credentials = ((user as any)._webauthnCredentials as any[]) ?? [];
    const idx = credentials.findIndex(
      (c: any) => c.CredentialId === req.CredentialId,
    );
    if (idx < 0) {
      throw new ResourceNotFoundError("Credential not found");
    }

    credentials.splice(idx, 1);

    await userPool.saveUser(ctx, {
      ...user,
      _webauthnCredentials: credentials,
      UserLastModifiedDate: clock.get(),
    } as any);

    return {};
  };
