import type {
  AdminInitiateAuthRequest,
  AdminInitiateAuthResponse,
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
import type { AppClient } from "../services/appClient";
import type { Context } from "../services/context";
import { startCustomAuth } from "../services/customAuth";
import { refreshTokens } from "../services/refreshTokens";
import type { Present } from "../services/sdkTypes";
import {
  afterPassword,
  assertUserAuthAllowed,
  passwordVerifierChallenge,
  type SignInRound,
  startUserAuth,
} from "../services/signIn";
import { refreshSecretHashUsername } from "../services/tokenVerifier";
import type { User } from "../services/userPoolService";
import type { Target } from "./Target";

export type AdminInitiateAuthTarget = Target<
  AdminInitiateAuthRequest,
  AdminInitiateAuthResponse
>;

type AdminInitiateAuthServices = Pick<
  Services,
  | "authSessions"
  | "clock"
  | "cognito"
  | "messages"
  | "otp"
  | "srpSessions"
  | "triggers"
  | "tokenGenerator"
  | "tokenVerifier"
>;

// AdminInitiateAuth passes ClientMetadata to pre token generation but not to PostAuthentication.
const signInRound = (
  req: Present<AdminInitiateAuthRequest>,
  userPool: UserPoolService,
  client: AppClient,
  user: User,
): SignInRound => ({
  userPool,
  client,
  user,
  clientMetadata: req.ClientMetadata,
  tokenClientMetadata: req.ClientMetadata,
});

const adminUserPasswordAuthFlow = async (
  ctx: Context,
  services: AdminInitiateAuthServices,
  req: Present<AdminInitiateAuthRequest>,
): Promise<AdminInitiateAuthResponse> => {
  if (!req.AuthParameters) {
    throw new InvalidParameterError(
      "Missing required parameter authParameters",
    );
  }

  if (!req.AuthParameters.USERNAME || !req.AuthParameters.PASSWORD) {
    throw new InvalidParameterError(
      "AuthParameters USERNAME and PASSWORD are required",
    );
  }

  const userPool = await services.cognito.getUserPoolForClientId(
    ctx,
    req.ClientId,
  );
  const userPoolClient = await services.cognito.getAppClient(ctx, req.ClientId);
  let user = await userPool.getUserByUsername(ctx, req.AuthParameters.USERNAME);

  if (
    !user &&
    services.triggers.enabled("UserMigration", userPool.options.Id)
  ) {
    // https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-migrate-user.html
    //
    // Amazon Cognito invokes [the User Migration] trigger when a user does not exist in the user pool at the time of
    // sign-in with a password, or in the forgot-password flow. After the Lambda function returns successfully, Amazon
    // Cognito creates the user in the user pool.
    user = await services.triggers.userMigration(ctx, {
      clientMetadata: {},
      validationData: {},
      userPoolId: userPool.options.Id,
      clientId: req.ClientId,
      username: req.AuthParameters.USERNAME,
      password: req.AuthParameters.PASSWORD,
      userAttributes: [],
    });
  }

  if (!user || !userPoolClient) {
    throw new NotAuthorizedError();
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
  services: AdminInitiateAuthServices,
  req: Present<AdminInitiateAuthRequest>,
): Promise<AdminInitiateAuthResponse> => {
  if (!req.AuthParameters) {
    throw new InvalidParameterError(
      "Missing required parameter authParameters",
    );
  }

  if (!req.AuthParameters.REFRESH_TOKEN) {
    throw new InvalidParameterError("AuthParameters REFRESH_TOKEN is required");
  }

  const userPoolClient = await services.cognito.getAppClient(ctx, req.ClientId);
  if (!userPoolClient) {
    throw new NotAuthorizedError();
  }
  const verified = await services.tokenVerifier.verifyRefreshToken(
    ctx,
    req.AuthParameters.REFRESH_TOKEN,
    req.ClientId,
  );
  services.tokenVerifier.verifySecretHash(
    userPoolClient,
    [refreshSecretHashUsername(verified.userPool, verified.user)],
    req.AuthParameters.SECRET_HASH,
  );

  const { tokens } = await refreshTokens(
    ctx,
    services,
    userPoolClient,
    verified,
    req.ClientMetadata,
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
  services: AdminInitiateAuthServices,
  req: Present<AdminInitiateAuthRequest>,
): Promise<AdminInitiateAuthResponse> => {
  if (!req.AuthParameters?.USERNAME) {
    throw new InvalidParameterError("Missing required parameter USERNAME");
  }
  if (!req.AuthParameters.SRP_A) {
    throw new InvalidParameterError("Missing required parameter SRP_A");
  }

  const userPool = await services.cognito.getUserPoolForClientId(
    ctx,
    req.ClientId,
  );
  const userPoolClient = await services.cognito.getAppClient(ctx, req.ClientId);
  const user = await userPool.getUserByUsername(
    ctx,
    req.AuthParameters.USERNAME,
  );
  if (!user || !userPoolClient) {
    throw new NotAuthorizedError();
  }
  if (!user.Enabled) {
    throw new NotAuthorizedError(TokenErrorMessages.userDisabled);
  }
  if (user.UserStatus === "RESET_REQUIRED") {
    throw new PasswordResetRequiredError();
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
  services: AdminInitiateAuthServices,
  req: Present<AdminInitiateAuthRequest>,
): Promise<AdminInitiateAuthResponse> => {
  const userPool = await services.cognito.getUserPoolForClientId(
    ctx,
    req.ClientId,
  );
  const userPoolClient = await services.cognito.getAppClient(ctx, req.ClientId);
  if (!userPoolClient) throw new NotAuthorizedError();
  assertUserAuthAllowed(userPoolClient);
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
  if (!user.Enabled) {
    throw new NotAuthorizedError(TokenErrorMessages.userDisabled);
  }
  if (user.UserStatus === "RESET_REQUIRED") {
    throw new PasswordResetRequiredError();
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
  services: AdminInitiateAuthServices,
  req: Present<AdminInitiateAuthRequest>,
): Promise<AdminInitiateAuthResponse> => {
  if (!req.AuthParameters?.USERNAME) {
    throw new InvalidParameterError("Missing required parameter USERNAME");
  }

  const userPool = await services.cognito.getUserPoolForClientId(
    ctx,
    req.ClientId,
  );
  const user = await userPool.getUserByUsername(
    ctx,
    req.AuthParameters.USERNAME,
  );
  if (!user) {
    throw new NotAuthorizedError();
  }
  if (!user.Enabled) {
    throw new NotAuthorizedError(TokenErrorMessages.userDisabled);
  }
  const userPoolClient = await services.cognito.getAppClient(ctx, req.ClientId);
  if (!userPoolClient) throw new NotAuthorizedError();

  return startCustomAuth(ctx, services, {
    userPool,
    user,
    client: userPoolClient,
    authParameters: req.AuthParameters,
    clientMetadata: req.ClientMetadata,
  });
};

export const AdminInitiateAuth =
  (services: AdminInitiateAuthServices): AdminInitiateAuthTarget =>
  async (ctx, req) => {
    const isRefresh =
      req.AuthFlow === "REFRESH_TOKEN_AUTH" || req.AuthFlow === "REFRESH_TOKEN";
    if (!isRefresh) {
      const client = await services.cognito.getAppClient(ctx, req.ClientId);
      if (client) {
        services.tokenVerifier.verifySecretHash(
          client,
          [req.AuthParameters?.USERNAME],
          req.AuthParameters?.SECRET_HASH,
        );
      }
    }

    if (
      req.AuthFlow === "ADMIN_USER_PASSWORD_AUTH" ||
      req.AuthFlow === "ADMIN_NO_SRP_AUTH"
    ) {
      return adminUserPasswordAuthFlow(ctx, services, req);
    } else if (req.AuthFlow === "USER_SRP_AUTH") {
      return userSrpAuthFlow(ctx, services, req);
    } else if (
      req.AuthFlow === "REFRESH_TOKEN_AUTH" ||
      req.AuthFlow === "REFRESH_TOKEN"
    ) {
      return refreshTokenAuthFlow(ctx, services, req);
    } else if (req.AuthFlow === "CUSTOM_AUTH") {
      return customAuthFlow(ctx, services, req);
    } else if (req.AuthFlow === "USER_AUTH") {
      return userAuthFlow(ctx, services, req);
    } else {
      throw new UnsupportedError(`AdminInitAuth with AuthFlow=${req.AuthFlow}`);
    }
  };
