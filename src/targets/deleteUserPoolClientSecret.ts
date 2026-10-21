import type {
  DeleteUserPoolClientSecretRequest,
  DeleteUserPoolClientSecretResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
import { clientSecretId } from "../services/appClient";
import type { Target } from "./Target";

export type DeleteUserPoolClientSecretTarget = Target<
  DeleteUserPoolClientSecretRequest,
  DeleteUserPoolClientSecretResponse
>;

export const DeleteUserPoolClientSecret =
  ({
    cognito,
    clock,
  }: Pick<Services, "cognito" | "clock">): DeleteUserPoolClientSecretTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const appClient = await cognito.getAppClient(ctx, req.ClientId);
    if (!appClient || appClient.UserPoolId !== req.UserPoolId) {
      throw new ResourceNotFoundError("App client not found");
    }
    if (
      !appClient.ClientSecret ||
      clientSecretId(appClient) !== req.ClientSecretId
    ) {
      throw new ResourceNotFoundError("Client secret not found");
    }

    const { ClientSecretCreateDate: _, ...withoutSecretDate } = appClient;
    await userPool.saveAppClient(ctx, {
      ...withoutSecretDate,
      ClientSecret: undefined,
      LastModifiedDate: clock.get(),
    });

    return {};
  };
