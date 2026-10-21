import type {
  SignUpRequest,
  SignUpResponse,
  UserStatusType,
} from "@aws-sdk/client-cognito-identity-provider";
import * as uuid from "uuid";
import {
  InvalidParameterError,
  NotAuthorizedError,
  UsernameExistsError,
} from "../errors";
import type { Messages, Services, UserPoolService } from "../services";
import { enforceAliasUniqueness } from "../services/aliases";
import type { Context } from "../services/context";
import { selectAppropriateDeliveryMethod } from "../services/messageDelivery/deliveryMethod";
import type { DeliveryDetails } from "../services/messageDelivery/messageDelivery";
import { assertPasswordConformsToPolicy } from "../services/passwordPolicy";
import {
  createSignUpSession,
  SIGN_UP_STEP,
  userAuthAllowed,
} from "../services/signUpSession";
import { verifyRequestSecretHash } from "../services/tokenVerifier";
import {
  assertNoDeveloperOnlyAttributes,
  attribute,
  attributesAppend,
  attributesInclude,
  attributesToRecord,
  type User,
} from "../services/userPoolService";
import type { Target } from "./Target";

export type SignUpTarget = Target<SignUpRequest, SignUpResponse>;

type SignUpServices = Pick<
  Services,
  | "clock"
  | "cognito"
  | "config"
  | "messages"
  | "otp"
  | "tokenVerifier"
  | "triggers"
> &
  Partial<Pick<Services, "authSessions">>;

const deliverWelcomeMessage = async (
  ctx: Context,
  code: string,
  clientId: string,
  user: User,
  userPool: UserPoolService,
  messages: Messages,
  clientMetadata: Record<string, string> | undefined,
): Promise<DeliveryDetails | null> => {
  const deliveryDetails = selectAppropriateDeliveryMethod(
    userPool.options.AutoVerifiedAttributes ?? [],
    user,
  );
  if (!deliveryDetails && !userPool.options.AutoVerifiedAttributes) {
    // From the console: When Cognito's default verification method is not enabled, you must use APIs or Lambda triggers
    // to verify phone numbers and email addresses as well as to confirm user accounts.
    return null;
  } else if (!deliveryDetails) {
    // TODO: I don't know what the real error message should be for this
    throw new InvalidParameterError(
      "User has no attribute matching desired auto verified attributes",
    );
  }

  await messages.deliver(
    ctx,
    "SignUp",
    clientId,
    userPool.options.Id,
    user,
    code,
    clientMetadata,
    deliveryDetails,
  );

  return deliveryDetails;
};

// An email or phone username names the attribute it collides on, as Cognito's message does.
const usernameExistsMessage = (
  userPool: UserPoolService,
  username: string,
): string | undefined => {
  const attributes = userPool.options.UsernameAttributes ?? [];
  if (attributes.includes("email") && username.includes("@")) {
    return "An account with the given email already exists.";
  }
  if (attributes.includes("phone_number") && /^\+\d+$/.test(username)) {
    return "An account with the given phone_number already exists.";
  }
  return undefined;
};

export const SignUp =
  ({
    clock,
    cognito,
    messages,
    otp,
    triggers,
    config,
    tokenVerifier,
    authSessions,
  }: SignUpServices): SignUpTarget =>
  async (ctx, req) => {
    // TODO: This should behave differently depending on if PreventUserExistenceErrors
    // is enabled on the updatedUser pool. This will be the default after Feb 2020.
    // See: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-managing-errors.html
    const userPool = await cognito.getUserPoolForClientId(ctx, req.ClientId);
    const client = await verifyRequestSecretHash(
      ctx,
      { cognito, tokenVerifier },
      req.ClientId,
      req.Username,
      req.SecretHash,
    );
    if (userPool.options.AdminCreateUserConfig?.AllowAdminCreateUserOnly) {
      throw new NotAuthorizedError(
        "SignUp is not permitted for this user pool",
      );
    }
    const existingUser = await userPool.getUserByUsername(ctx, req.Username);
    if (existingUser) {
      throw new UsernameExistsError(
        usernameExistsMessage(userPool, req.Username),
      );
    }

    assertPasswordConformsToPolicy(
      config,
      userPool.options,
      req.Password as string,
      "signUp",
    );

    const sub = uuid.v4();
    const attributes =
      (attributesInclude("sub", req.UserAttributes)
        ? req.UserAttributes
        : [{ Name: "sub", Value: sub }, ...(req.UserAttributes ?? [])]) ?? [];
    let userStatus: UserStatusType = "UNCONFIRMED";

    let username = req.Username;
    if (userPool.options.UsernameAttributes?.includes("email")) {
      // user pool is configured to use the email attribute as the user's username
      if (!req.Username.includes("@")) {
        // naive validation that the username is an email
        throw new InvalidParameterError("Username should be an email.");
      }

      if (!attributesInclude("email", attributes)) {
        attributes.push({ Name: "email", Value: req.Username });
      }

      // when the username is an email address, cognito uses the sub as the username in
      // requests/responses, triggers etc...
      username = sub;
    }

    // Validate custom attributes against pool schema
    const schemaAttributes = userPool.options.SchemaAttributes ?? [];
    assertNoDeveloperOnlyAttributes(
      (req.UserAttributes ?? []).map((x) => x.Name),
      schemaAttributes,
    );
    if (req.UserAttributes) {
      for (const attr of req.UserAttributes) {
        if (attr.Name.startsWith("custom:")) {
          const schemaDef = schemaAttributes.find((s) => s.Name === attr.Name);
          if (!schemaDef) {
            throw new InvalidParameterError(
              `user.${attr.Name}: Attribute does not exist in the schema.`,
            );
          }
          if (
            schemaDef.StringAttributeConstraints &&
            attr.Value !== undefined
          ) {
            const { MinLength, MaxLength } =
              schemaDef.StringAttributeConstraints;
            if (MinLength && attr.Value.length < Number(MinLength)) {
              throw new InvalidParameterError(
                `user.${attr.Name}: String value is shorter than the minimum length.`,
              );
            }
            if (MaxLength && attr.Value.length > Number(MaxLength)) {
              throw new InvalidParameterError(
                `user.${attr.Name}: String value is longer than the maximum length.`,
              );
            }
          }
          if (
            schemaDef.NumberAttributeConstraints &&
            attr.Value !== undefined
          ) {
            const num = Number(attr.Value);
            if (Number.isNaN(num)) {
              throw new InvalidParameterError(
                `user.${attr.Name}: Value is not a valid number.`,
              );
            }
            const { MinValue, MaxValue } = schemaDef.NumberAttributeConstraints;
            if (MinValue && num < Number(MinValue)) {
              throw new InvalidParameterError(
                `user.${attr.Name}: Number value is less than the minimum value.`,
              );
            }
            if (MaxValue && num > Number(MaxValue)) {
              throw new InvalidParameterError(
                `user.${attr.Name}: Number value is greater than the maximum value.`,
              );
            }
          }
        }
      }
    }
    // Validate required attributes against the final attribute set (includes
    // auto-added ones like email when UsernameAttributes=[email]).
    for (const schemaDef of schemaAttributes) {
      if (
        schemaDef.Required &&
        schemaDef.Name &&
        !schemaDef.Name.startsWith("sub") &&
        !attributesInclude(schemaDef.Name, attributes)
      ) {
        throw new InvalidParameterError(
          `Attributes did not conform to the schema: ${schemaDef.Name}: The attribute is required`,
        );
      }
    }

    if (triggers.enabled("PreSignUp", userPool.options.Id)) {
      const { autoConfirmUser, autoVerifyEmail, autoVerifyPhone } =
        await triggers.preSignUp(ctx, {
          clientId: req.ClientId,
          clientMetadata: req.ClientMetadata,
          source: "PreSignUp_SignUp",
          userAttributes: attributes,
          username,
          userPoolId: userPool.options.Id,
          validationData: req.ValidationData
            ? attributesToRecord(req.ValidationData)
            : undefined,
        });

      if (autoConfirmUser) {
        userStatus = "CONFIRMED";
      }
      const isEmailUsername =
        userPool.options.UsernameAttributes?.includes("email");
      const hasEmailAttribute = attributesInclude("email", attributes);

      if (isEmailUsername && !hasEmailAttribute) {
        attributes.push({ Name: "email", Value: req.Username });
      }
      if ((isEmailUsername || hasEmailAttribute) && autoVerifyEmail) {
        attributes.push({ Name: "email_verified", Value: "true" });
      }
      if (attributesInclude("phone_number", attributes) && autoVerifyPhone) {
        attributes.push({ Name: "phone_number_verified", Value: "true" });
      }
    }

    const now = clock.get();

    const updatedUser: User = {
      Attributes: attributes,
      Enabled: true,
      Password: req.Password as string,
      RefreshTokens: [],
      UserCreateDate: now,
      UserLastModifiedDate: now,
      Username: username,
      UserStatus: userStatus,
    };

    // PreSignUp auto-verification moves an existing alias instead of failing (pre sign-up trigger docs).
    await enforceAliasUniqueness(ctx, userPool, clock, username, attributes, {
      forceAliasCreation: true,
      usernameConflict: "UsernameExistsException",
    });

    const code = otp();

    // An auto-confirmed user is not sent a confirmation code.
    const deliveryDetails =
      userStatus === "CONFIRMED"
        ? null
        : await deliverWelcomeMessage(
            ctx,
            code,
            req.ClientId,
            updatedUser,
            userPool,
            messages,
            req.ClientMetadata,
          );

    await userPool.saveUser(ctx, {
      ...updatedUser,
      ConfirmationCode: code,
    });

    if (
      updatedUser.UserStatus === "CONFIRMED" &&
      triggers.enabled("PostConfirmation", userPool.options.Id)
    ) {
      await triggers.postConfirmation(ctx, {
        clientId: req.ClientId,
        clientMetadata: req.ClientMetadata,
        source: "PostConfirmation_ConfirmSignUp",
        username,
        userPoolId: userPool.options.Id,

        // not sure whether this is a one off for PostConfirmation, or whether we should be adding cognito:user_status
        // into every place we send attributes to lambdas
        userAttributes: attributesAppend(
          updatedUser.Attributes,
          attribute("cognito:user_status", updatedUser.UserStatus),
        ),
      });
    }

    return {
      CodeDeliveryDetails: deliveryDetails ?? undefined,
      UserConfirmed: updatedUser.UserStatus === "CONFIRMED",
      UserSub: sub,
      ...(authSessions && client && userAuthAllowed(client)
        ? {
            Session: createSignUpSession(
              authSessions,
              client,
              username,
              SIGN_UP_STEP,
            ),
          }
        : {}),
    };
  };
