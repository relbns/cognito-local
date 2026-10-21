import type {
  ForgotPasswordRequest,
  ForgotPasswordResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import {
  InvalidParameterError,
  NotAuthorizedError,
  TokenErrorMessages,
  UserNotFoundError,
} from "../errors";
import type { Services, UserPoolService } from "../services";
import type { Context } from "../services/context";
import {
  recoveryAttributeOrder,
  selectRecoveryDeliveryMethod,
} from "../services/messageDelivery/deliveryMethod";
import { countPasswordResetAttempt } from "../services/signInLockout";
import { verifyRequestSecretHash } from "../services/tokenVerifier";
import {
  preventsUserExistenceErrors,
  simulatedDelivery,
  USERNAME_CLIENT_NOT_FOUND,
} from "../services/userExistence";
import type { User } from "../services/userPoolService";
import type { Target } from "./Target";

export type ForgotPasswordTarget = Target<
  ForgotPasswordRequest,
  ForgotPasswordResponse
>;

type ForgotPasswordServices = Pick<
  Services,
  "clock" | "cognito" | "messages" | "otp" | "tokenVerifier" | "triggers"
> &
  Partial<Pick<Services, "config">>;

// An unknown user is looked up through UserMigration (UserMigration_ForgotPassword) when the pool has it.
const findOrMigrateUser = async (
  ctx: Context,
  triggers: ForgotPasswordServices["triggers"],
  userPool: UserPoolService,
  req: Pick<ForgotPasswordRequest, "ClientMetadata"> & {
    ClientId: string;
    Username: string;
  },
): Promise<User | null> => {
  const user = await userPool.getUserByUsername(ctx, req.Username);
  if (user || !triggers.enabled("UserMigration", userPool.options.Id)) {
    return user;
  }
  try {
    return await triggers.userMigration(ctx, {
      clientId: req.ClientId,
      clientMetadata: req.ClientMetadata,
      password: undefined,
      source: "UserMigration_ForgotPassword",
      userAttributes: [],
      username: req.Username,
      userPoolId: userPool.options.Id,
      validationData: undefined,
    });
  } catch (e) {
    if (e instanceof NotAuthorizedError) return null;
    throw e;
  }
};

export const ForgotPassword =
  ({
    cognito,
    clock,
    messages,
    otp,
    tokenVerifier,
    triggers,
    config,
  }: ForgotPasswordServices): ForgotPasswordTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPoolForClientId(ctx, req.ClientId);
    const client = await verifyRequestSecretHash(
      ctx,
      { cognito, tokenVerifier },
      req.ClientId,
      req.Username,
      req.SecretHash,
    );
    const user = await findOrMigrateUser(ctx, triggers, userPool, req);
    const recovery = userPool.options.AccountRecoverySetting;
    const simulated = () => ({
      CodeDeliveryDetails: simulatedDelivery(
        req.Username,
        recoveryAttributeOrder(recovery),
      ),
    });
    if (!user || !user.Enabled) {
      if (preventsUserExistenceErrors(client)) return simulated();
      throw user
        ? new NotAuthorizedError(TokenErrorMessages.userDisabled)
        : new UserNotFoundError(USERNAME_CLIENT_NOT_FOUND);
    }

    if (user.UserStatus === "FORCE_CHANGE_PASSWORD") {
      throw new NotAuthorizedError(
        "User password cannot be reset in the current state.",
      );
    }

    const deliveryDetails = selectRecoveryDeliveryMethod(recovery, user);
    if (!deliveryDetails) {
      if (preventsUserExistenceErrors(client)) return simulated();
      throw new InvalidParameterError(
        "Cannot reset password for the user as there is no registered/verified email or phone_number",
      );
    }

    await countPasswordResetAttempt(ctx, config, userPool, user, clock.get());

    const code = otp();
    await messages.deliver(
      ctx,
      "ForgotPassword",
      req.ClientId,
      userPool.options.Id,
      user,
      code,
      req.ClientMetadata,
      deliveryDetails,
    );

    await userPool.updateUser(ctx, user, (latest) => ({
      ...latest,
      UserLastModifiedDate: clock.get(),
      ConfirmationCode: code,
    }));

    return {
      CodeDeliveryDetails: deliveryDetails,
    };
  };
