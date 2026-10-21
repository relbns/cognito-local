import type {
  ConfirmForgotPasswordRequest,
  ConfirmForgotPasswordResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import {
  CodeMismatchError,
  ExpiredCodeError,
  NotAuthorizedError,
  TokenErrorMessages,
  UserNotFoundError,
} from "../errors";
import type { Services } from "../services";
import { assertPasswordConformsToPolicy } from "../services/passwordPolicy";
import { countPasswordResetAttempt } from "../services/signInLockout";
import { verifyRequestSecretHash } from "../services/tokenVerifier";
import {
  preventsUserExistenceErrors,
  USERNAME_CLIENT_NOT_FOUND,
} from "../services/userExistence";
import type { User } from "../services/userPoolService";
import { attribute, attributesAppend } from "../services/userPoolService";
import type { Target } from "./Target";

export type ConfirmForgotPasswordTarget = Target<
  ConfirmForgotPasswordRequest,
  ConfirmForgotPasswordResponse
>;

type ConfirmForgotPasswordServices = Pick<
  Services,
  "clock" | "cognito" | "tokenVerifier" | "triggers"
> &
  Partial<Pick<Services, "config">>;

export const ConfirmForgotPassword =
  ({
    cognito,
    clock,
    triggers,
    config,
    tokenVerifier,
  }: ConfirmForgotPasswordServices): ConfirmForgotPasswordTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPoolForClientId(ctx, req.ClientId);
    const client = await verifyRequestSecretHash(
      ctx,
      { cognito, tokenVerifier },
      req.ClientId,
      req.Username,
      req.SecretHash,
    );
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user || !user.Enabled) {
      if (preventsUserExistenceErrors(client)) {
        throw new CodeMismatchError();
      }
      throw user
        ? new NotAuthorizedError(TokenErrorMessages.userDisabled)
        : new UserNotFoundError(USERNAME_CLIENT_NOT_FOUND);
    }

    const counted = await countPasswordResetAttempt(
      ctx,
      config,
      userPool,
      user,
      clock.get(),
    );
    if (!user.ConfirmationCode) {
      throw new ExpiredCodeError();
    }
    if (user.ConfirmationCode !== req.ConfirmationCode) {
      throw new CodeMismatchError();
    }

    assertPasswordConformsToPolicy(config, userPool.options, req.Password);

    const updatedUser: User = {
      ...counted,
      UserLastModifiedDate: clock.get(),
      UserStatus: "CONFIRMED",
      ConfirmationCode: undefined,
      Password: req.Password,
    };

    await userPool.saveUser(ctx, updatedUser);

    if (triggers.enabled("PostConfirmation", userPool.options.Id)) {
      await triggers.postConfirmation(ctx, {
        clientId: req.ClientId,
        clientMetadata: req.ClientMetadata,
        source: "PostConfirmation_ConfirmForgotPassword",
        username: updatedUser.Username,
        userPoolId: userPool.options.Id,

        // not sure whether this is a one off for PostConfirmation, or whether we should be adding cognito:user_status
        // into every place we send attributes to lambdas
        userAttributes: attributesAppend(
          updatedUser.Attributes,
          attribute("cognito:user_status", updatedUser.UserStatus),
        ),
      });
    }

    return {};
  };
