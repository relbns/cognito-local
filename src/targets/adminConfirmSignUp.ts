import type {
  AdminConfirmSignUpRequest,
  AdminConfirmSignUpResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { NotAuthorizedError, UserNotFoundError } from "../errors";
import type { Services } from "../services";
import type { User } from "../services/userPoolService";
import { attribute, attributesAppend } from "../services/userPoolService";
import type { Target } from "./Target";

export type AdminConfirmSignUpTarget = Target<
  AdminConfirmSignUpRequest,
  AdminConfirmSignUpResponse
>;

type AdminConfirmSignUpServices = Pick<
  Services,
  "clock" | "cognito" | "triggers"
>;

export const AdminConfirmSignUp =
  ({
    clock,
    cognito,
    triggers,
  }: AdminConfirmSignUpServices): AdminConfirmSignUpTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) {
      throw new UserNotFoundError("User does not exist.");
    }

    if (user.UserStatus !== "UNCONFIRMED") {
      throw new NotAuthorizedError(
        `User cannot be confirmed. Current status is ${user.UserStatus}`,
      );
    }

    const updatedUser: User = {
      ...user,
      UserLastModifiedDate: clock.get(),
      UserStatus: "CONFIRMED",
    };

    await userPool.saveUser(ctx, updatedUser);

    if (triggers.enabled("PostConfirmation", req.UserPoolId)) {
      await triggers.postConfirmation(ctx, {
        source: "PostConfirmation_ConfirmSignUp",
        clientId: null,
        clientMetadata: req.ClientMetadata,
        username: updatedUser.Username,
        userPoolId: req.UserPoolId,

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
