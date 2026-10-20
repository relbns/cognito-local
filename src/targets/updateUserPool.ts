import type {
  UpdateUserPoolRequest,
  UpdateUserPoolResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { normalizePasswordPolicy } from "../services/passwordPolicy";
import type { UserPool } from "../services/userPoolService";
import type { Target } from "./Target";

export type UpdateUserPoolTarget = Target<
  UpdateUserPoolRequest,
  UpdateUserPoolResponse
>;

type UpdateUserPoolServices = Pick<Services, "cognito">;

export const UpdateUserPool =
  ({ cognito }: UpdateUserPoolServices): UpdateUserPoolTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);

    const updatedUserPool: UserPool = {
      ...userPool.options,
      AccountRecoverySetting: req.AccountRecoverySetting,
      AdminCreateUserConfig: req.AdminCreateUserConfig,
      AutoVerifiedAttributes: req.AutoVerifiedAttributes,
      DeviceConfiguration: req.DeviceConfiguration,
      EmailConfiguration: req.EmailConfiguration,
      EmailVerificationMessage: req.EmailVerificationMessage,
      EmailVerificationSubject: req.EmailVerificationSubject,
      LambdaConfig: req.LambdaConfig,
      MfaConfiguration: req.MfaConfiguration,
      Policies: req.Policies && {
        ...req.Policies,
        PasswordPolicy: normalizePasswordPolicy(req.Policies.PasswordPolicy),
      },
      SmsAuthenticationMessage: req.SmsAuthenticationMessage,
      SmsConfiguration: req.SmsConfiguration,
      SmsVerificationMessage: req.SmsVerificationMessage,
      UserPoolAddOns: req.UserPoolAddOns,
      UserPoolTags: req.UserPoolTags,
      VerificationMessageTemplate: req.VerificationMessageTemplate,
    };

    await userPool.updateOptions(ctx, updatedUserPool);

    return {};
  };
