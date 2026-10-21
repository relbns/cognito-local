import type {
  CreateTermsRequest,
  CreateTermsResponse,
  TermsType,
} from "@aws-sdk/client-cognito-identity-provider";
import * as uuid from "uuid";
import type { Services } from "../services";
import type { Target } from "./Target";

export type CreateTermsTarget = Target<CreateTermsRequest, CreateTermsResponse>;

export const CreateTerms =
  ({
    cognito,
    clock,
  }: Pick<Services, "cognito" | "clock">): CreateTermsTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const now = clock.get();

    const terms: TermsType = {
      TermsId: uuid.v4(),
      UserPoolId: req.UserPoolId,
      ClientId: req.ClientId,
      TermsName: req.TermsName,
      TermsSource: req.TermsSource,
      Enforcement: req.Enforcement,
      Links: req.Links ?? {},
      CreationDate: now,
      LastModifiedDate: now,
    };

    const existing = ((userPool.options as any)._terms as TermsType[]) ?? [];
    existing.push(terms);

    await userPool.updateOptions(ctx, {
      ...userPool.options,
      _terms: existing,
    } as any);

    return { Terms: terms };
  };
