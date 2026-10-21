import type { CryptoService } from "../crypto";
import type { CustomSMSSenderTriggerResponse, Lambda } from "../lambda";
import type { Attribute } from "../sdkTypes";
import { attributesToRecord } from "../userPoolService";
import type { Trigger } from "./trigger";

export type CustomSMSSenderTrigger = Trigger<
  {
    code: string;
    source:
      | "CustomSMSSender_AdminCreateUser"
      | "CustomSMSSender_Authentication"
      | "CustomSMSSender_ForgotPassword"
      | "CustomSMSSender_ResendCode"
      | "CustomSMSSender_SignUp"
      | "CustomSMSSender_UpdateUserAttribute"
      | "CustomSMSSender_VerifyUserAttribute";
    userPoolId: string;
    clientId: string | null;
    username: string;
    userAttributes: Attribute[];

    /**
     * Source: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-custom-sms-sender.html
     */
    clientMetadata: Record<string, string> | undefined;
  },
  CustomSMSSenderTriggerResponse | null
>;

interface CustomSMSSenderServices {
  lambda: Lambda;
  crypto: CryptoService;
}

export const CustomSMSSender =
  ({ lambda, crypto }: CustomSMSSenderServices): CustomSMSSenderTrigger =>
  async (
    ctx,
    {
      clientId,
      clientMetadata,
      code,
      source,
      userAttributes,
      username,
      userPoolId,
    },
  ) => {
    try {
      const encrypted = await crypto.encrypt(ctx, code);

      await lambda.invoke(ctx, "CustomSMSSender", {
        code: encrypted,
        clientId,
        clientMetadata,
        triggerSource: source,
        userAttributes: attributesToRecord(userAttributes),
        username,
        userPoolId,
      });

      return {};
    } catch (ex) {
      ctx.logger.error(ex);
      return null;
    }
  };
