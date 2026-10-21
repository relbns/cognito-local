import type {
  ListUserPoolClientSecretsRequest,
  ListUserPoolClientSecretsResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
import { clientSecretCreateDate, clientSecretId } from "../services/appClient";
import type { Target } from "./Target";

export type ListUserPoolClientSecretsTarget = Target<
  ListUserPoolClientSecretsRequest,
  ListUserPoolClientSecretsResponse
>;

export const ListUserPoolClientSecrets =
  ({ cognito }: Pick<Services, "cognito">): ListUserPoolClientSecretsTarget =>
  async (ctx, req) => {
    await cognito.getUserPool(ctx, req.UserPoolId);
    const appClient = await cognito.getAppClient(ctx, req.ClientId);
    if (!appClient || appClient.UserPoolId !== req.UserPoolId) {
      throw new ResourceNotFoundError("App client not found");
    }

    return {
      ClientSecrets: appClient.ClientSecret
        ? [
            {
              ClientSecretId: clientSecretId(appClient),
              ClientSecretCreateDate: clientSecretCreateDate(appClient),
            },
          ]
        : [],
    };
  };
