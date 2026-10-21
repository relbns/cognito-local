import type {
  TermsType,
  UpdateTermsRequest,
  UpdateTermsResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
import type { Target } from "./Target";

export type UpdateTermsTarget = Target<UpdateTermsRequest, UpdateTermsResponse>;

export const UpdateTerms =
  ({
    cognito,
    clock,
  }: Pick<Services, "cognito" | "clock">): UpdateTermsTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const items = ((userPool.options as any)._terms as TermsType[]) ?? [];
    const idx = items.findIndex((t) => t.TermsId === req.TermsId);
    if (idx < 0) {
      throw new ResourceNotFoundError("Terms not found");
    }

    const current = items[idx];
    items[idx] = {
      ...current,
      TermsName: req.TermsName ?? current.TermsName,
      TermsSource: req.TermsSource ?? current.TermsSource,
      Enforcement: req.Enforcement ?? current.Enforcement,
      Links: req.Links ?? current.Links,
      LastModifiedDate: clock.get(),
    };

    await userPool.updateOptions(ctx, {
      ...userPool.options,
      _terms: items,
    } as any);

    return { Terms: items[idx] };
  };
