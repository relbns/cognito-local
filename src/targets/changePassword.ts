import type {
  ChangePasswordRequest,
  ChangePasswordResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { NotAuthorizedError } from "../errors";
import type { Services } from "../services";
import { assertPasswordConformsToPolicy } from "../services/passwordPolicy";
import type { Target } from "./Target";

export type ChangePasswordTarget = Target<
  ChangePasswordRequest,
  ChangePasswordResponse
>;

type ChangePasswordServices = Pick<Services, "clock" | "tokenVerifier"> &
  Partial<Pick<Services, "config">>;

export const ChangePassword =
  ({
    clock,
    config,
    tokenVerifier,
  }: ChangePasswordServices): ChangePasswordTarget =>
  async (ctx, req) => {
    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    if (req.PreviousPassword !== user.Password) {
      throw new NotAuthorizedError("Incorrect username or password.");
    }

    assertPasswordConformsToPolicy(
      config,
      userPool.options,
      req.ProposedPassword,
    );

    await userPool.saveUser(ctx, {
      ...user,
      Password: req.ProposedPassword,
      UserLastModifiedDate: clock.get(),
    });

    return {};
  };
