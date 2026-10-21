import type {
  DeliveryMediumType,
  InitiateAuthRequest,
  InitiateAuthResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { v4 } from "uuid";
import {
  InvalidParameterError,
  NotAuthorizedError,
  PasswordResetRequiredError,
  UnsupportedError,
  UserNotConfirmedException,
} from "../errors";
import type { Services, UserPoolService } from "../services";
import type { AppClient } from "../services/appClient";
import type { Context } from "../services/context";
import {
  passwordVerifierChallengeParameters,
  startCustomAuth,
} from "../services/customAuth";
import { enabledMfaMethods, isMfaRequired } from "../services/mfa";
import { refreshTokens } from "../services/refreshTokens";
import type { Present } from "../services/sdkTypes";
import { refreshSecretHashUsername } from "../services/tokenVerifier";
import {
  attributesToRecord,
  attributeValue,
  type MFAOption,
  type User,
} from "../services/userPoolService";
import type { Target } from "./Target";

export type InitiateAuthTarget = Target<
  InitiateAuthRequest,
  InitiateAuthResponse
>;

type InitiateAuthServices = Pick<
  Services,
  | "authSessions"
  | "clock"
  | "cognito"
  | "messages"
  | "otp"
  | "tokenGenerator"
  | "tokenVerifier"
  | "triggers"
>;

const smsMfaChallenge = async (
  ctx: Context,
  user: User,
  req: Present<InitiateAuthRequest>,
  userPool: UserPoolService,
  services: InitiateAuthServices,
): Promise<InitiateAuthResponse> => {
  const smsMfaOption = user.MFAOptions?.find(
    (x): x is MFAOption & { DeliveryMedium: DeliveryMediumType } =>
      x.DeliveryMedium === "SMS",
  );
  if (!smsMfaOption) {
    throw new UnsupportedError("SMS_MFA without SMS MFAOption");
  }

  const deliveryDestination = attributeValue(
    smsMfaOption.AttributeName,
    user.Attributes,
  );
  if (!deliveryDestination) {
    throw new UnsupportedError(`SMS_MFA without ${smsMfaOption.AttributeName}`);
  }

  const code = services.otp();
  await services.messages.deliver(
    ctx,
    "Authentication",
    req.ClientId,
    userPool.options.Id,
    user,
    code,
    req.ClientMetadata,
    {
      DeliveryMedium: smsMfaOption.DeliveryMedium,
      AttributeName: smsMfaOption.AttributeName,
      Destination: deliveryDestination,
    },
  );

  await userPool.updateUser(ctx, user, (latest) => ({
    ...latest,
    MFACode: code,
  }));

  return {
    ChallengeName: "SMS_MFA",
    ChallengeParameters: {
      CODE_DELIVERY_DELIVERY_MEDIUM: "SMS",
      CODE_DELIVERY_DESTINATION: deliveryDestination,
      USER_ID_FOR_SRP: user.Username,
    },
    Session: v4(),
  };
};

const softwareTokenMfaChallenge = (user: User): InitiateAuthResponse => ({
  ChallengeName: "SOFTWARE_TOKEN_MFA",
  ChallengeParameters: {
    USER_ID_FOR_SRP: user.Username,
    ...(user.SoftwareTokenMfaConfiguration?.FriendlyDeviceName
      ? {
          FRIENDLY_DEVICE_NAME:
            user.SoftwareTokenMfaConfiguration.FriendlyDeviceName,
        }
      : {}),
  },
  Session: v4(),
});

const verifyMfaChallenge = async (
  ctx: Context,
  user: User,
  req: Present<InitiateAuthRequest>,
  userPool: UserPoolService,
  services: InitiateAuthServices,
): Promise<InitiateAuthResponse> => {
  const methods = enabledMfaMethods(user);
  if (methods.length === 0) {
    throw new NotAuthorizedError();
  }

  if (methods.length > 1) {
    return {
      ChallengeName: "SELECT_MFA_TYPE",
      ChallengeParameters: {
        USER_ID_FOR_SRP: user.Username,
        MFAS_CAN_CHOOSE: JSON.stringify(methods),
      },
      Session: v4(),
    };
  }

  if (methods[0] === "SOFTWARE_TOKEN_MFA") {
    return softwareTokenMfaChallenge(user);
  }
  return smsMfaChallenge(ctx, user, req, userPool, services);
};

const verifyPasswordChallenge = async (
  ctx: Context,
  user: User,
  _req: Present<InitiateAuthRequest>,
  userPool: UserPoolService,
  userPoolClient: AppClient,
  services: InitiateAuthServices,
): Promise<InitiateAuthResponse> => {
  const userGroups = await userPool.listUserGroupMembership(ctx, user);

  const tokens = await services.tokenGenerator.generate(
    ctx,
    user,
    userGroups,
    userPoolClient,
    // The docs for the pre-token generation trigger only say that the ClientMetadata is passed as part of the
    // AdminRespondToAuthChallenge and RespondToAuthChallenge triggers.
    //
    // source: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html
    undefined,
    "Authentication",
  );

  await userPool.storeRefreshToken(ctx, tokens.RefreshToken, user);

  return {
    ChallengeName: undefined,
    ChallengeParameters: {},
    AuthenticationResult: tokens,
  };
};

const newPasswordChallenge = (user: User): InitiateAuthResponse => ({
  ChallengeName: "NEW_PASSWORD_REQUIRED",
  ChallengeParameters: {
    USER_ID_FOR_SRP: user.Username,
    requiredAttributes: JSON.stringify([]),
    userAttributes: JSON.stringify(attributesToRecord(user.Attributes)),
  },
  Session: v4(),
});

const userPasswordAuthFlow = async (
  ctx: Context,
  req: Present<InitiateAuthRequest>,
  userPool: UserPoolService,
  userPoolClient: AppClient,
  services: InitiateAuthServices,
): Promise<InitiateAuthResponse> => {
  if (!req.AuthParameters) {
    throw new InvalidParameterError(
      "Missing required parameter authParameters",
    );
  }

  let user = await userPool.getUserByUsername(ctx, req.AuthParameters.USERNAME);

  if (
    !user &&
    services.triggers.enabled("UserMigration", userPool.options.Id)
  ) {
    // https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-migrate-user.html
    //
    // Amazon Cognito invokes [the User Migration] trigger when a user does not exist in the user pool at the time
    // of sign-in with a password, or in the forgot-password flow. After the Lambda function returns successfully,
    // Amazon Cognito creates the user in the user pool.
    user = await services.triggers.userMigration(ctx, {
      clientId: req.ClientId,
      password: req.AuthParameters.PASSWORD,
      userAttributes: [],
      username: req.AuthParameters.USERNAME,
      userPoolId: userPool.options.Id,

      // UserMigration triggered by InitiateAuth passes the request ClientMetadata as ValidationData and nothing as
      // the ClientMetadata.
      //
      // Source: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-migrate-user.html#cognito-user-pools-lambda-trigger-syntax-user-migration
      clientMetadata: undefined,
      validationData: req.ClientMetadata,
    });
  }

  if (!user) {
    throw new NotAuthorizedError();
  }
  if (user.UserStatus === "RESET_REQUIRED") {
    throw new PasswordResetRequiredError();
  }
  if (user.UserStatus === "FORCE_CHANGE_PASSWORD") {
    return newPasswordChallenge(user);
  }
  if (user.Password !== req.AuthParameters.PASSWORD) {
    throw new NotAuthorizedError("Incorrect username or password.");
  }
  if (user.UserStatus === "UNCONFIRMED") {
    throw new UserNotConfirmedException();
  }

  if (isMfaRequired(userPool.options, user)) {
    return verifyMfaChallenge(ctx, user, req, userPool, services);
  }

  if (services.triggers.enabled("PostAuthentication", userPool.options.Id)) {
    await services.triggers.postAuthentication(ctx, {
      clientId: req.ClientId,
      // As per the InitiateAuth docs, ClientMetadata is not passed to PostAuthentication when called from InitiateAuth
      // Source: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html#API_InitiateAuth_RequestSyntax
      clientMetadata: undefined,
      source: "PostAuthentication_Authentication",
      userAttributes: user.Attributes,
      username: user.Username,
      userPoolId: userPool.options.Id,
    });
  }

  return verifyPasswordChallenge(
    ctx,
    user,
    req,
    userPool,
    userPoolClient,
    services,
  );
};

const refreshTokenAuthFlow = async (
  ctx: Context,
  req: Present<InitiateAuthRequest>,
  userPool: UserPoolService,
  userPoolClient: AppClient,
  services: InitiateAuthServices,
): Promise<InitiateAuthResponse> => {
  if (!req.AuthParameters) {
    throw new InvalidParameterError(
      "Missing required parameter authParameters",
    );
  }

  if (!req.AuthParameters.REFRESH_TOKEN) {
    throw new InvalidParameterError("AuthParameters REFRESH_TOKEN is required");
  }

  const verified = await services.tokenVerifier.verifyRefreshToken(
    ctx,
    req.AuthParameters.REFRESH_TOKEN,
    req.ClientId,
  );
  services.tokenVerifier.verifySecretHash(
    userPoolClient,
    [refreshSecretHashUsername(userPool, verified.user)],
    req.AuthParameters.SECRET_HASH,
  );

  const { tokens } = await refreshTokens(
    ctx,
    services,
    userPoolClient,
    verified,
  );

  return {
    ChallengeName: undefined,
    Session: undefined,
    ChallengeParameters: undefined,
    AuthenticationResult: {
      AccessToken: tokens.AccessToken,
      RefreshToken: undefined,
      IdToken: tokens.IdToken,
      NewDeviceMetadata: undefined,
      TokenType: tokens.TokenType,
      ExpiresIn: tokens.ExpiresIn,
    },
  };
};

const userSrpAuthFlow = async (
  ctx: Context,
  req: Present<InitiateAuthRequest>,
  userPool: UserPoolService,
  _userPoolClient: AppClient,
  _services: InitiateAuthServices,
): Promise<InitiateAuthResponse> => {
  if (!req.AuthParameters) {
    throw new InvalidParameterError(
      "Missing required parameter authParameters",
    );
  }
  if (!req.AuthParameters.SRP_A) {
    throw new InvalidParameterError("Missing required parameter SRP_A");
  }
  if (!req.AuthParameters.USERNAME) {
    throw new InvalidParameterError("Missing required parameter USERNAME");
  }

  const user = await userPool.getUserByUsername(
    ctx,
    req.AuthParameters.USERNAME,
  );
  if (!user) {
    throw new NotAuthorizedError();
  }

  if (user.UserStatus === "RESET_REQUIRED") {
    throw new PasswordResetRequiredError();
  }
  if (user.UserStatus === "UNCONFIRMED") {
    throw new UserNotConfirmedException();
  }

  // Simplified SRP: return fake SRP_B, SALT, SECRET_BLOCK
  // The emulator doesn't perform real SRP math — PASSWORD_VERIFIER
  // response handler will verify the password directly.
  return {
    ChallengeName: "PASSWORD_VERIFIER",
    ChallengeParameters: passwordVerifierChallengeParameters(user),
    Session: v4(),
  };
};

const customAuthFlow = async (
  ctx: Context,
  req: Present<InitiateAuthRequest>,
  userPool: UserPoolService,
  userPoolClient: AppClient,
  services: InitiateAuthServices,
): Promise<InitiateAuthResponse> => {
  if (!req.AuthParameters?.USERNAME) {
    throw new InvalidParameterError("Missing required parameter USERNAME");
  }

  const user = await userPool.getUserByUsername(
    ctx,
    req.AuthParameters.USERNAME,
  );
  if (!user) {
    throw new NotAuthorizedError();
  }

  return startCustomAuth(ctx, services, {
    userPool,
    user,
    client: userPoolClient,
    authParameters: req.AuthParameters,
    clientMetadata: req.ClientMetadata,
  });
};

export const InitiateAuth =
  (services: InitiateAuthServices): InitiateAuthTarget =>
  async (ctx, req) => {
    const userPool = await services.cognito.getUserPoolForClientId(
      ctx,
      req.ClientId,
    );
    const userPoolClient = await services.cognito.getAppClient(
      ctx,
      req.ClientId,
    );
    if (!userPoolClient) {
      throw new NotAuthorizedError();
    }

    if (
      req.AuthFlow !== "REFRESH_TOKEN" &&
      req.AuthFlow !== "REFRESH_TOKEN_AUTH"
    ) {
      services.tokenVerifier.verifySecretHash(
        userPoolClient,
        [req.AuthParameters?.USERNAME],
        req.AuthParameters?.SECRET_HASH,
      );
    }

    if (req.AuthFlow === "USER_PASSWORD_AUTH") {
      return userPasswordAuthFlow(ctx, req, userPool, userPoolClient, services);
    } else if (req.AuthFlow === "USER_SRP_AUTH") {
      return userSrpAuthFlow(ctx, req, userPool, userPoolClient, services);
    } else if (
      req.AuthFlow === "REFRESH_TOKEN" ||
      req.AuthFlow === "REFRESH_TOKEN_AUTH"
    ) {
      return refreshTokenAuthFlow(ctx, req, userPool, userPoolClient, services);
    } else if (req.AuthFlow === "CUSTOM_AUTH") {
      return customAuthFlow(ctx, req, userPool, userPoolClient, services);
    } else {
      throw new UnsupportedError(`InitAuth with AuthFlow=${req.AuthFlow}`);
    }
  };
