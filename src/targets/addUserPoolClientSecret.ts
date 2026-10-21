import type {
  AddUserPoolClientSecretRequest,
  AddUserPoolClientSecretResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
import {
  clientSecretCreateDate,
  clientSecretId,
  newId,
} from "../services/appClient";
import type { Target } from "./Target";

export type AddUserPoolClientSecretTarget = Target<
  AddUserPoolClientSecretRequest,
  AddUserPoolClientSecretResponse
>;

export const AddUserPoolClientSecret =
  ({
    cognito,
    clock,
  }: Pick<Services, "cognito" | "clock">): AddUserPoolClientSecretTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const appClient = await cognito.getAppClient(ctx, req.ClientId);
    if (!appClient || appClient.UserPoolId !== req.UserPoolId) {
      throw new ResourceNotFoundError("App client not found");
    }

    const now = clock.get();
    const updated = {
      ...appClient,
      ClientSecret: req.ClientSecret ?? newId(),
      ClientSecretCreateDate: now,
      LastModifiedDate: now,
    };
    await userPool.saveAppClient(ctx, updated);

    return {
      ClientSecretDescriptor: {
        ClientSecretId: clientSecretId(updated),
        ClientSecretValue: updated.ClientSecret,
        ClientSecretCreateDate: clientSecretCreateDate(updated),
      },
    };
  };
