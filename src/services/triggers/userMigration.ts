import * as uuid from "uuid";
import {
  NotAuthorizedError,
  ResourceNotFoundError,
  UserLambdaValidationError,
  UsernameExistsError,
} from "../../errors";
import { enforceAliasUniqueness } from "../aliases";
import type { Clock } from "../clock";
import type { CognitoService } from "../cognitoService";
import type { Lambda, UserMigrationTriggerResponse } from "../lambda";
import type { Attribute } from "../sdkTypes";
import {
  attributesFromRecord,
  attributesToRecord,
  type User,
} from "../userPoolService";
import type { Trigger } from "./trigger";

export type UserMigrationTrigger = Trigger<
  {
    userPoolId: string;
    clientId: string;
    username: string;
    /** Absent in the forgot-password flow. */
    password: string | undefined;
    userAttributes: Attribute[];
    source?: "UserMigration_Authentication" | "UserMigration_ForgotPassword";

    /**
     * One or more key-value pairs that you can provide as custom input to the Lambda function that you specify for the
     * migrate user trigger. You can pass this data to your Lambda function by using the ClientMetadata parameter in the
     * AdminRespondToAuthChallenge and ForgotPassword API actions.
     *
     * Source: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-migrate-user.html#cognito-user-pools-lambda-trigger-syntax-user-migration
     */
    clientMetadata: Record<string, string> | undefined;

    /**
     * One or more key-value pairs containing the validation data in the user's sign-in request. You can pass this data to
     * your Lambda function by using the ClientMetadata parameter in the InitiateAuth and AdminInitiateAuth API actions.
     *
     * Source: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-migrate-user.html#cognito-user-pools-lambda-trigger-syntax-user-migration
     */
    validationData: Record<string, string> | undefined;
  },
  User
>;

interface UserMigrationServices {
  clock: Clock;
  cognitoClient: CognitoService;
  lambda: Lambda;
}

export const UserMigration =
  ({
    lambda,
    cognitoClient,
    clock,
  }: UserMigrationServices): UserMigrationTrigger =>
  async (
    ctx,
    {
      clientId,
      clientMetadata,
      password,
      userAttributes,
      username,
      userPoolId,
      validationData,
      source = "UserMigration_Authentication",
    },
  ) => {
    const forgotPassword = source === "UserMigration_ForgotPassword";
    const userPool = await cognitoClient.getUserPoolForClientId(ctx, clientId);
    if (!userPool) {
      throw new ResourceNotFoundError();
    }

    let result: UserMigrationTriggerResponse;

    try {
      result = await lambda.invoke(ctx, "UserMigration", {
        clientId,
        clientMetadata,
        password: forgotPassword ? undefined : password,
        triggerSource: source,
        userAttributes: attributesToRecord(userAttributes),
        username,
        userPoolId,
        validationData: forgotPassword ? undefined : validationData,
      });
    } catch (_ex) {
      throw new NotAuthorizedError();
    }

    const now = clock.get();
    const sub = uuid.v4();
    const { username: requestedUsername, ...returnedAttributes } =
      result.userAttributes ?? {};
    const attributes: Record<string, string> = {
      ...returnedAttributes,
      sub,
    };
    const usernameAttributes = userPool.options.UsernameAttributes ?? [];
    if (usernameAttributes.length) {
      const signInAttribute =
        username.includes("@") && usernameAttributes.includes("email")
          ? "email"
          : usernameAttributes.includes("phone_number")
            ? "phone_number"
            : undefined;
      if (signInAttribute && !attributes[signInAttribute]) {
        attributes[signInAttribute] = username;
      }
    }

    if (result.enableSMSMFA && !attributes.phone_number) {
      throw new UserLambdaValidationError(
        "UserMigration failed with error enableSMSMFA requires a phone_number attribute.",
      );
    }

    const user: User = {
      Attributes: attributesFromRecord(attributes),
      Enabled: true,
      Password: password ?? "",
      UserCreateDate: now,
      UserLastModifiedDate: now,
      // Pools with email or phone as the username identify users by sub, as SignUp does.
      Username: usernameAttributes.length ? sub : requestedUsername || username,
      // A user migrated by the forgot-password flow has no password until ConfirmForgotPassword.
      UserStatus:
        !forgotPassword && result.finalUserStatus === "CONFIRMED"
          ? "CONFIRMED"
          : "RESET_REQUIRED",
      RefreshTokens: [],
      ...(result.enableSMSMFA
        ? {
            UserMFASettingList: ["SMS_MFA"],
            PreferredMfaSetting: "SMS_MFA",
          }
        : {}),
    };

    if (await userPool.getUserByUsername(ctx, user.Username)) {
      throw new UsernameExistsError();
    }

    await enforceAliasUniqueness(
      ctx,
      userPool,
      clock,
      user.Username,
      user.Attributes,
      { forceAliasCreation: !!result.forceAliasCreation },
    );

    await userPool.saveUser(ctx, user);

    return user;
  };
