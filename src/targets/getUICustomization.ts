import type {
  GetUICustomizationRequest,
  GetUICustomizationResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import type { Target } from "./Target";

export type GetUICustomizationTarget = Target<
  GetUICustomizationRequest,
  GetUICustomizationResponse
>;

export const GetUICustomization =
  ({ cognito }: Pick<Services, "cognito">): GetUICustomizationTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const customization = (userPool.options as any)._uiCustomization ?? {
      UserPoolId: req.UserPoolId,
      ClientId: req.ClientId ?? "ALL",
    };

    return { UICustomization: customization };
  };
