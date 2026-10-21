import type {
  CreateUserPoolClientRequest,
  CreateUserPoolClientResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import {
  type AppClient,
  assertAuthSessionValidity,
  assertRefreshTokenRotation,
  newId,
} from "../services/appClient";
import { assertTokenValidity } from "../services/tokenGenerator";
import { appClientToResponseObject } from "./responses";
import type { Target } from "./Target";

export type CreateUserPoolClientTarget = Target<
  CreateUserPoolClientRequest,
  CreateUserPoolClientResponse
>;

type CreateUserPoolClientServices = Pick<Services, "clock" | "cognito">;

export const CreateUserPoolClient =
  ({
    clock,
    cognito,
  }: CreateUserPoolClientServices): CreateUserPoolClientTarget =>
  async (ctx, req) => {
    assertAuthSessionValidity(req.AuthSessionValidity);
    assertRefreshTokenRotation(req.RefreshTokenRotation);
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);

    const appClient: AppClient = {
      AccessTokenValidity: req.AccessTokenValidity,
      AllowedOAuthFlows: req.AllowedOAuthFlows,
      AllowedOAuthFlowsUserPoolClient: req.AllowedOAuthFlowsUserPoolClient,
      AllowedOAuthScopes: req.AllowedOAuthScopes,
      AnalyticsConfiguration: req.AnalyticsConfiguration,
      AuthSessionValidity: req.AuthSessionValidity,
      CallbackURLs: req.CallbackURLs,
      ClientId: newId(),
      ClientName: req.ClientName,
      ClientSecret: req.GenerateSecret ? newId() : undefined,
      CreationDate: clock.get(),
      DefaultRedirectURI: req.DefaultRedirectURI,
      EnableTokenRevocation: req.EnableTokenRevocation ?? true,
      ExplicitAuthFlows: req.ExplicitAuthFlows,
      IdTokenValidity: req.IdTokenValidity,
      LastModifiedDate: clock.get(),
      LogoutURLs: req.LogoutURLs,
      PreventUserExistenceErrors: req.PreventUserExistenceErrors,
      ReadAttributes: req.ReadAttributes,
      RefreshTokenRotation: req.RefreshTokenRotation,
      RefreshTokenValidity: req.RefreshTokenValidity,
      SupportedIdentityProviders: req.SupportedIdentityProviders,
      TokenValidityUnits: {
        AccessToken: req.TokenValidityUnits?.AccessToken ?? "hours",
        IdToken: req.TokenValidityUnits?.IdToken ?? "hours",
        RefreshToken: req.TokenValidityUnits?.RefreshToken ?? "days",
      },
      UserPoolId: req.UserPoolId,
      WriteAttributes: req.WriteAttributes,
    };

    assertTokenValidity(appClient);
    await userPool.saveAppClient(ctx, appClient);

    return {
      UserPoolClient: appClientToResponseObject(appClient),
    };
  };
