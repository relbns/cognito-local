import type {
  ResendConfirmationCodeRequest,
  ResendConfirmationCodeResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { InvalidParameterError, UserNotFoundError } from "../errors";
import type { Services } from "../services";
import { selectAppropriateDeliveryMethod } from "../services/messageDelivery/deliveryMethod";
import { verifyRequestSecretHash } from "../services/tokenVerifier";
import type { Target } from "./Target";

export type ResendConfirmationCodeTarget = Target<
  ResendConfirmationCodeRequest,
  ResendConfirmationCodeResponse
>;

type ResendConfirmationCodeServices = Pick<
  Services,
  "clock" | "cognito" | "messages" | "otp" | "tokenVerifier"
>;

export const ResendConfirmationCode =
  ({
    cognito,
    clock,
    messages,
    otp,
    tokenVerifier,
  }: ResendConfirmationCodeServices): ResendConfirmationCodeTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPoolForClientId(ctx, req.ClientId);
    await verifyRequestSecretHash(
      ctx,
      { cognito, tokenVerifier },
      req.ClientId,
      req.Username,
      req.SecretHash,
    );
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) {
      throw new UserNotFoundError();
    }

    const deliveryDetails = selectAppropriateDeliveryMethod(
      userPool.options.AutoVerifiedAttributes ?? [],
      user,
    );
    if (!deliveryDetails) {
      throw new InvalidParameterError(
        "User has no attribute matching desired auto verified attributes",
      );
    }

    const code = otp();

    await messages.deliver(
      ctx,
      "ResendCode",
      req.ClientId,
      userPool.options.Id,
      user,
      code,
      req.ClientMetadata,
      deliveryDetails,
    );

    await userPool.updateUser(ctx, user, (latest) => ({
      ...latest,
      ConfirmationCode: code,
      UserLastModifiedDate: clock.get(),
    }));

    return {
      CodeDeliveryDetails: deliveryDetails,
    };
  };
