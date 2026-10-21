import type {
  ListTermsRequest,
  ListTermsResponse,
  TermsType,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { paginate } from "../services/pagination";
import type { Target } from "./Target";

export type ListTermsTarget = Target<ListTermsRequest, ListTermsResponse>;

export const ListTerms =
  ({ cognito }: Pick<Services, "cognito">): ListTermsTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const items = ((userPool.options as any)._terms as TermsType[]) ?? [];

    const { items: page, nextToken } = paginate(
      items,
      req.MaxResults,
      req.NextToken,
    );

    return {
      Terms: page.map((t) => ({
        TermsId: t.TermsId,
        TermsName: t.TermsName,
        Enforcement: t.Enforcement,
        CreationDate: t.CreationDate,
        LastModifiedDate: t.LastModifiedDate,
      })),
      NextToken: nextToken,
    };
  };
