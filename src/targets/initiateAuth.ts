import type {
  InitiateAuthRequest,
  InitiateAuthResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import {
  InvalidParameterError,
  NotAuthorizedError,
  PasswordResetRequiredError,
  TokenErrorMessages,
  UnsupportedError,
  UserNotConfirmedException,
} from "../errors";
import type { Services, UserPoolService } from "../services";
import {
  type AppClient,
  refreshTokenRotationEnabled,
} from "../services/appClient";
import type { Context } from "../services/context";
import { startCustomAuth } from "../services/customAuth";
import { refreshTokens } from "../services/refreshTokens";
import type { Present } from "../services/sdkTypes";
import {
  afterPassword,
  assertUserAuthAllowed,
  passwordVerifierChallenge,
  phantomPasswordVerifierChallenge,
  type SignInRound,
  startPhantomUserAuth,
  startUserAuth,
} from "../services/signIn";
import { refreshSecretHashUsername } from "../services/tokenVerifier";
import { runPreAuthentication } from "../services/triggers/preAuthentication";
import {
  INCORRECT_CREDENTIALS,
  phantomUser,
  preventsUserExistenceErrors,
  unknownUserSignInError,
} from "../services/userExistence";
import type { User } from "../services/userPoolService";
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
  | "srpSessions"
  | "tokenGenerator"
  | "tokenVerifier"
  | "triggers"
>;

// With PreventUserExistenceErrors ENABLED an imported user gets the generic failure (import tool docs).
const resetRequiredError = (client: AppClient): Error =>
  preventsUserExistenceErrors(client)
    ? new NotAuthorizedError(INCORRECT_CREDENTIALS)
    : new PasswordResetRequiredError();

// InitiateAuth passes no ClientMetadata to PostAuthentication or pre token generation (InitiateAuth API reference).
const signInRound = (
  req: Present<InitiateAuthRequest>,
  userPool: UserPoolService,
  client: AppClient,
  user: User,
): SignInRound => ({
  userPool,
  client,
  user,
  clientMetadata: req.ClientMetadata,
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

  await runPreAuthentication(ctx, services.triggers, {
    client: userPoolClient,
    user,
    username: req.AuthParameters.USERNAME,
    userPoolId: userPool.options.Id,
    validationData: req.ClientMetadata,
  });

  if (!user) {
    throw unknownUserSignInError(userPoolClient);
  }
  if (user.UserStatus === "RESET_REQUIRED") {
    throw resetRequiredError(userPoolClient);
  }
  if (user.Password !== req.AuthParameters.PASSWORD) {
    throw new NotAuthorizedError("Incorrect username or password.");
  }
  if (!user.Enabled) {
    throw new NotAuthorizedError(TokenErrorMessages.userDisabled);
  }
  if (user.UserStatus === "UNCONFIRMED") {
    throw new UserNotConfirmedException();
  }

  return afterPassword(ctx, services, {
    ...signInRound(req, userPool, userPoolClient, user),
    deviceKey: req.AuthParameters.DEVICE_KEY,
  });
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

  if (refreshTokenRotationEnabled(userPoolClient)) {
    throw new InvalidParameterError(
      "REFRESH_TOKEN_AUTH flow not enabled for this client",
    );
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
  userPoolClient: AppClient,
  services: InitiateAuthServices,
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
  await runPreAuthentication(ctx, services.triggers, {
    client: userPoolClient,
    user,
    username: req.AuthParameters.USERNAME,
    userPoolId: userPool.options.Id,
    validationData: req.ClientMetadata,
  });
  if (!user) {
    if (!preventsUserExistenceErrors(userPoolClient)) {
      throw unknownUserSignInError(userPoolClient);
    }
    return phantomPasswordVerifierChallenge(
      services,
      signInRound(
        req,
        userPool,
        userPoolClient,
        phantomUser(req.AuthParameters.USERNAME),
      ),
      req.AuthParameters.SRP_A,
    );
  }
  if (!user.Enabled) {
    throw new NotAuthorizedError(TokenErrorMessages.userDisabled);
  }

  if (user.UserStatus === "RESET_REQUIRED") {
    throw resetRequiredError(userPoolClient);
  }
  if (user.UserStatus === "UNCONFIRMED") {
    throw new UserNotConfirmedException();
  }

  return passwordVerifierChallenge(
    services,
    {
      ...signInRound(req, userPool, userPoolClient, user),
      deviceKey: req.AuthParameters.DEVICE_KEY,
    },
    req.AuthParameters.SRP_A,
  );
};

const userAuthFlow = async (
  ctx: Context,
  req: Present<InitiateAuthRequest>,
  userPool: UserPoolService,
  userPoolClient: AppClient,
  services: InitiateAuthServices,
): Promise<InitiateAuthResponse> => {
  assertUserAuthAllowed(userPoolClient);
  if (!req.AuthParameters?.USERNAME) {
    throw new InvalidParameterError("Missing required parameter USERNAME");
  }

  const user = await userPool.getUserByUsername(
    ctx,
    req.AuthParameters.USERNAME,
  );
  await runPreAuthentication(ctx, services.triggers, {
    client: userPoolClient,
    user,
    username: req.AuthParameters.USERNAME,
    userPoolId: userPool.options.Id,
    validationData: req.ClientMetadata,
  });
  if (!user) {
    if (!preventsUserExistenceErrors(userPoolClient)) {
      throw unknownUserSignInError(userPoolClient);
    }
    return startPhantomUserAuth(
      services,
      signInRound(
        req,
        userPool,
        userPoolClient,
        phantomUser(req.AuthParameters.USERNAME),
      ),
      req.AuthParameters,
    );
  }
  if (!user.Enabled) {
    throw new NotAuthorizedError(TokenErrorMessages.userDisabled);
  }
  if (user.UserStatus === "RESET_REQUIRED") {
    throw resetRequiredError(userPoolClient);
  }
  if (user.UserStatus === "UNCONFIRMED") {
    throw new UserNotConfirmedException();
  }

  return startUserAuth(
    ctx,
    services,
    {
      ...signInRound(req, userPool, userPoolClient, user),
      deviceKey: req.AuthParameters.DEVICE_KEY,
    },
    req.AuthParameters,
  );
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
  await runPreAuthentication(ctx, services.triggers, {
    client: userPoolClient,
    user,
    username: req.AuthParameters.USERNAME,
    userPoolId: userPool.options.Id,
    validationData: req.ClientMetadata,
  });
  if (!user && !preventsUserExistenceErrors(userPoolClient)) {
    throw unknownUserSignInError(userPoolClient);
  }
  if (user && !user.Enabled) {
    throw new NotAuthorizedError(TokenErrorMessages.userDisabled);
  }

  return startCustomAuth(ctx, services, {
    userPool,
    user: user ?? phantomUser(req.AuthParameters.USERNAME),
    userNotFound: !user,
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
    } else if (req.AuthFlow === "USER_AUTH") {
      return userAuthFlow(ctx, req, userPool, userPoolClient, services);
    } else {
      throw new UnsupportedError(`InitAuth with AuthFlow=${req.AuthFlow}`);
    }
  };
