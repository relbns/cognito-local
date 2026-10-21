import type {
  ListWebAuthnCredentialsRequest,
  ListWebAuthnCredentialsResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { paginate } from "../services/pagination";
import { credentialDescription } from "../services/webAuthn";
import type { Target } from "./Target";

export type ListWebAuthnCredentialsTarget = Target<
  ListWebAuthnCredentialsRequest,
  ListWebAuthnCredentialsResponse
>;

export const ListWebAuthnCredentials =
  ({
    tokenVerifier,
  }: Pick<Services, "tokenVerifier">): ListWebAuthnCredentialsTarget =>
  async (ctx, req) => {
    const { user } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    const { items, nextToken } = paginate(
      (user.WebAuthnCredentials ?? []).map(credentialDescription),
      req.MaxResults,
      req.NextToken,
    );

    return {
      Credentials: items,
      NextToken: nextToken,
    };
  };
