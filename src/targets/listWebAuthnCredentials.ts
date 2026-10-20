import type { Services } from "../services";
import { paginate } from "../services/pagination";
import type { Target } from "./Target";

interface ListWebAuthnCredentialsRequest {
  AccessToken: string;
  NextToken?: string;
  MaxResults?: number;
}
interface ListWebAuthnCredentialsResponse {
  Credentials?: any[];
  NextToken?: string;
}

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

    const credentials = ((user as any)._webauthnCredentials as any[]) ?? [];

    const { items, nextToken } = paginate(
      credentials,
      req.MaxResults,
      req.NextToken,
    );

    return {
      Credentials: items,
      NextToken: nextToken,
    };
  };
