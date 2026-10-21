import type {
  DeleteUserAttributesRequest,
  DeleteUserAttributesResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import {
  assertNoDeveloperOnlyAttributes,
  attributesRemove,
} from "../services/userPoolService";
import type { Target } from "./Target";

export type DeleteUserAttributesTarget = Target<
  DeleteUserAttributesRequest,
  DeleteUserAttributesResponse
>;

type DeleteUserAttributesServices = Pick<Services, "clock" | "tokenVerifier">;

export const DeleteUserAttributes =
  ({
    clock,
    tokenVerifier,
  }: DeleteUserAttributesServices): DeleteUserAttributesTarget =>
  async (ctx, req) => {
    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    assertNoDeveloperOnlyAttributes(
      req.UserAttributeNames,
      userPool.options.SchemaAttributes,
    );

    const updatedUser = {
      ...user,
      Attributes: attributesRemove(user.Attributes, ...req.UserAttributeNames),
      UserLastModifiedDate: clock.get(),
    };

    await userPool.saveUser(ctx, updatedUser);

    return {};
  };
