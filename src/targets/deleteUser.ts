import type { DeleteUserRequest } from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import type { Target } from "./Target";

export type DeleteUserTarget = Target<DeleteUserRequest, object>;

type DeleteUserServices = Pick<Services, "tokenVerifier">;

export const DeleteUser =
  ({ tokenVerifier }: DeleteUserServices): DeleteUserTarget =>
  async (ctx, req) => {
    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    await userPool.deleteUser(ctx, user);

    return {};
  };
