import type {
  ForgotPasswordRequest,
  ForgotPasswordResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import {
  NotAuthorizedError,
  UnsupportedError,
  UserNotFoundError,
} from "../errors";
import type { Services, UserPoolService } from "../services";
import type { Context } from "../services/context";
import type { DeliveryDetails } from "../services/messageDelivery/messageDelivery";
import { verifyRequestSecretHash } from "../services/tokenVerifier";
import { attributeValue, type User } from "../services/userPoolService";
import type { Target } from "./Target";

export type ForgotPasswordTarget = Target<
  ForgotPasswordRequest,
  ForgotPasswordResponse
>;

type ForgotPasswordServices = Pick<
  Services,
  "clock" | "cognito" | "messages" | "otp" | "tokenVerifier" | "triggers"
>;

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
  }: ForgotPasswordServices): ForgotPasswordTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPoolForClientId(ctx, req.ClientId);
    await verifyRequestSecretHash(
      ctx,
      { cognito, tokenVerifier },
      req.ClientId,
      req.Username,
      req.SecretHash,
    );
    const user = await findOrMigrateUser(ctx, triggers, userPool, req);
    if (!user) {
      throw new UserNotFoundError("Username/client id combination not found.");
    }

    const userEmail = attributeValue("email", user.Attributes);
    if (!userEmail) {
      throw new UnsupportedError("ForgotPassword without email on user");
    }

    const deliveryDetails: DeliveryDetails = {
      AttributeName: "email",
      DeliveryMedium: "EMAIL",
      Destination: userEmail,
    };

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
