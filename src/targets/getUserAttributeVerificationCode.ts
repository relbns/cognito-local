import type {
  GetUserAttributeVerificationCodeRequest,
  GetUserAttributeVerificationCodeResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { InvalidParameterError } from "../errors";
import type { Messages, Services, UserPoolService } from "../services";
import type { Context } from "../services/context";
import { selectAppropriateDeliveryMethod } from "../services/messageDelivery/deliveryMethod";
import type { Present } from "../services/sdkTypes";
import type { User } from "../services/userPoolService";
import type { Target } from "./Target";

const sendAttributeVerificationCode = async (
  ctx: Context,
  userPool: UserPoolService,
  user: User,
  messages: Messages,
  req: Present<GetUserAttributeVerificationCodeRequest>,
  code: string,
) => {
  const deliveryDetails = selectAppropriateDeliveryMethod(
    userPool.options.AutoVerifiedAttributes ?? [],
    user,
  );
  if (!deliveryDetails) {
    // TODO: I don't know what the real error message should be for this
    throw new InvalidParameterError(
      "User has no attribute matching desired auto verified attributes",
    );
  }

  await messages.deliver(
    ctx,
    "VerifyUserAttribute",
    null,
    userPool.options.Id,
    user,
    code,
    req.ClientMetadata,
    deliveryDetails,
  );
};

export type GetUserAttributeVerificationCodeTarget = Target<
  GetUserAttributeVerificationCodeRequest,
  GetUserAttributeVerificationCodeResponse
>;

type GetUserAttributeVerificationCodeServices = Pick<
  Services,
  "messages" | "otp" | "tokenVerifier"
>;

export const GetUserAttributeVerificationCode =
  ({
    messages,
    otp,
    tokenVerifier,
  }: GetUserAttributeVerificationCodeServices): GetUserAttributeVerificationCodeTarget =>
  async (ctx, req) => {
    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    const code = otp();

    await userPool.saveUser(ctx, {
      ...user,
      AttributeVerificationCode: code,
    });

    await sendAttributeVerificationCode(
      ctx,
      userPool,
      user,
      messages,
      req,
      code,
    );

    return {};
  };
