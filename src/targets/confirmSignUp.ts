import type {
  ConfirmSignUpRequest,
  ConfirmSignUpResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import {
  CodeMismatchError,
  ExpiredCodeError,
  NotAuthorizedError,
  UserNotFoundError,
} from "../errors";
import type { Services } from "../services";
import { enforceAliasUniqueness } from "../services/aliases";
import { selectAppropriateDeliveryMethod } from "../services/messageDelivery/deliveryMethod";
import { verifyRequestSecretHash } from "../services/tokenVerifier";
import {
  preventsUserExistenceErrors,
  USERNAME_CLIENT_NOT_FOUND,
} from "../services/userExistence";
import type { User } from "../services/userPoolService";
import { attribute, attributesAppend } from "../services/userPoolService";
import type { Target } from "./Target";

export type ConfirmSignUpTarget = Target<
  ConfirmSignUpRequest,
  ConfirmSignUpResponse
>;

export const ConfirmSignUp =
  ({
    cognito,
    clock,
    triggers,
    tokenVerifier,
  }: Pick<
    Services,
    "clock" | "cognito" | "tokenVerifier" | "triggers"
  >): ConfirmSignUpTarget =>
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
    if (!user) {
      throw preventsUserExistenceErrors(client)
        ? new CodeMismatchError()
        : new UserNotFoundError(USERNAME_CLIENT_NOT_FOUND);
    }

    if (user.UserStatus !== "UNCONFIRMED") {
      throw new NotAuthorizedError(
        `User cannot be confirmed. Current status is ${user.UserStatus}`,
      );
    }
    if (!user.ConfirmationCode) {
      throw new ExpiredCodeError();
    }

    if (user.ConfirmationCode !== req.ConfirmationCode) {
      throw new CodeMismatchError();
    }

    // Confirming with the code verifies the attribute it was delivered to.
    const verifiedByCode = selectAppropriateDeliveryMethod(
      userPool.options.AutoVerifiedAttributes ?? [],
      user,
    )?.AttributeName;

    const updatedUser: User = {
      ...user,
      Attributes: verifiedByCode
        ? attributesAppend(
            user.Attributes,
            attribute(`${verifiedByCode}_verified`, "true"),
          )
        : user.Attributes,
      UserStatus: "CONFIRMED",
      ConfirmationCode: undefined,
      UserLastModifiedDate: clock.get(),
    };

    await enforceAliasUniqueness(
      ctx,
      userPool,
      clock,
      updatedUser.Username,
      updatedUser.Attributes,
      { forceAliasCreation: req.ForceAliasCreation },
    );

    await userPool.saveUser(ctx, updatedUser);

    if (triggers.enabled("PostConfirmation", userPool.options.Id)) {
      await triggers.postConfirmation(ctx, {
        clientId: req.ClientId,
        clientMetadata: req.ClientMetadata,
        source: "PostConfirmation_ConfirmSignUp",
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
