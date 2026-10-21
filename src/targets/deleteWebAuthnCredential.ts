import type {
  DeleteWebAuthnCredentialRequest,
  DeleteWebAuthnCredentialResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
import type { Target } from "./Target";

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

    if (
      !(user.WebAuthnCredentials ?? []).some(
        (c) => c.CredentialId === req.CredentialId,
      )
    ) {
      throw new ResourceNotFoundError("Credential not found");
    }

    await userPool.updateUser(ctx, user, (latest) => ({
      ...latest,
      WebAuthnCredentials: (latest.WebAuthnCredentials ?? []).filter(
        (c) => c.CredentialId !== req.CredentialId,
      ),
      UserLastModifiedDate: clock.get(),
    }));

    return {};
  };
