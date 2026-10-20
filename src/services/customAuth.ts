import * as crypto from "node:crypto";
import type { InitiateAuthResponse } from "@aws-sdk/client-cognito-identity-provider";
import {
  InvalidParameterError,
  InvalidPasswordError,
  NotAuthorizedError,
  UnsupportedError,
} from "../errors";
import type { AppClient } from "./appClient";
import type { AuthSessions, ChallengeResult } from "./authSessions";
import type { Context } from "./context";
import type { Services } from "./index";
import type { User, UserPoolService } from "./userPoolService";

export type CustomAuthServices = Pick<
  Services,
  "authSessions" | "tokenGenerator" | "triggers"
>;

export type CustomAuthResponse = Pick<
  InitiateAuthResponse,
  "AuthenticationResult" | "ChallengeName" | "ChallengeParameters" | "Session"
>;

interface CustomAuthRound {
  userPool: UserPoolService;
  user: User;
  client: AppClient;
  history: ChallengeResult[];
  clientMetadata?: Record<string, string>;
  postAuthenticationClientMetadata?: Record<string, string>;
}

export const passwordVerifierChallengeParameters = (user: User) => ({
  SALT: crypto.randomBytes(16).toString("hex"),
  SRP_B: crypto.randomBytes(128).toString("hex"),
  SECRET_BLOCK: crypto.randomBytes(64).toString("base64"),
  USER_ID_FOR_SRP: user.Username,
  USERNAME: user.Username,
});

const triggerBase = (round: CustomAuthRound) => ({
  clientId: round.client.ClientId,
  userAttributes: round.user.Attributes,
  username: round.user.Username,
  userPoolId: round.userPool.options.Id,
  session: round.history,
  clientMetadata: round.clientMetadata,
});

const issueTokens = async (
  ctx: Context,
  services: CustomAuthServices,
  round: CustomAuthRound,
): Promise<CustomAuthResponse> => {
  const { userPool, user, client } = round;
  if (services.triggers.enabled("PostAuthentication", userPool.options.Id)) {
    await services.triggers.postAuthentication(ctx, {
      clientId: client.ClientId,
      clientMetadata: round.postAuthenticationClientMetadata,
      source: "PostAuthentication_Authentication",
      userAttributes: user.Attributes,
      username: user.Username,
      userPoolId: userPool.options.Id,
    });
  }
  const userGroups = await userPool.listUserGroupMembership(ctx, user);
  const tokens = await services.tokenGenerator.generate(
    ctx,
    user,
    userGroups,
    client,
    round.clientMetadata,
    "Authentication",
  );
  await userPool.storeRefreshToken(ctx, tokens.RefreshToken, user);
  return { ChallengeParameters: {}, AuthenticationResult: tokens };
};

const runCustomAuthRound = async (
  ctx: Context,
  services: CustomAuthServices,
  round: CustomAuthRound,
): Promise<CustomAuthResponse> => {
  const define = await services.triggers.defineAuthChallenge(
    ctx,
    triggerBase(round),
  );

  if (define.failAuthentication) {
    throw new NotAuthorizedError("Incorrect username or password.");
  }
  if (define.issueTokens) {
    return issueTokens(ctx, services, round);
  }

  const challengeName = define.challengeName || "CUSTOM_CHALLENGE";
  const newSession = (
    pendingChallenge: Parameters<AuthSessions["create"]>[0]["pendingChallenge"],
  ) =>
    services.authSessions.create(
      {
        userPoolId: round.userPool.options.Id,
        clientId: round.client.ClientId,
        username: round.user.Username,
        clientMetadata: round.clientMetadata,
        history: round.history,
        pendingChallenge,
      },
      round.client.AuthSessionValidity,
    );

  if (challengeName === "PASSWORD_VERIFIER") {
    return {
      ChallengeName: "PASSWORD_VERIFIER",
      ChallengeParameters: passwordVerifierChallengeParameters(round.user),
      Session: newSession({ challengeName, privateChallengeParameters: {} }),
    };
  }

  if (challengeName !== "CUSTOM_CHALLENGE") {
    throw new UnsupportedError(
      `CUSTOM_AUTH with DefineAuthChallenge challengeName=${challengeName}`,
    );
  }
  if (
    !services.triggers.enabled("CreateAuthChallenge", round.userPool.options.Id)
  ) {
    throw new UnsupportedError(
      "CUSTOM_AUTH requires CreateAuthChallenge trigger",
    );
  }

  const created = await services.triggers.createAuthChallenge(ctx, {
    ...triggerBase(round),
    challengeName,
  });

  return {
    ChallengeName: "CUSTOM_CHALLENGE",
    ChallengeParameters: {
      ...created.publicChallengeParameters,
      USERNAME: round.user.Username,
      USER_ID_FOR_SRP: round.user.Username,
    },
    Session: newSession({
      challengeName,
      privateChallengeParameters: created.privateChallengeParameters ?? {},
      challengeMetadata: created.challengeMetadata,
    }),
  };
};

export const startCustomAuth = async (
  ctx: Context,
  services: CustomAuthServices,
  {
    userPool,
    user,
    client,
    authParameters,
    clientMetadata,
  }: {
    userPool: UserPoolService;
    user: User;
    client: AppClient;
    authParameters?: Record<string, string>;
    clientMetadata?: Record<string, string>;
  },
): Promise<CustomAuthResponse> => {
  if (!services.triggers.enabled("DefineAuthChallenge", userPool.options.Id)) {
    throw new UnsupportedError(
      "CUSTOM_AUTH requires DefineAuthChallenge trigger",
    );
  }

  return runCustomAuthRound(ctx, services, {
    userPool,
    user,
    client,
    history: authParameters?.SRP_A
      ? [{ challengeName: "SRP_A", challengeResult: true }]
      : [],
    clientMetadata,
  });
};

export const isCustomAuthSession = (
  services: Pick<Services, "authSessions">,
  sessionId: string,
): boolean => services.authSessions.peek(sessionId) !== undefined;

export const respondToCustomAuthChallenge = async (
  ctx: Context,
  services: CustomAuthServices,
  {
    userPool,
    user,
    client,
    sessionId,
    challengeName,
    challengeResponses,
    clientMetadata,
  }: {
    userPool: UserPoolService;
    user: User;
    client: AppClient;
    sessionId: string;
    challengeName: string;
    challengeResponses: Record<string, string>;
    clientMetadata?: Record<string, string>;
  },
): Promise<CustomAuthResponse> => {
  const session = services.authSessions.take(sessionId);
  if (
    session.clientId !== client.ClientId ||
    session.userPoolId !== userPool.options.Id ||
    session.username !== user.Username
  ) {
    throw new NotAuthorizedError("Invalid session for the user.");
  }
  if (session.pendingChallenge.challengeName !== challengeName) {
    throw new InvalidParameterError(
      `Expected ChallengeName ${session.pendingChallenge.challengeName}`,
    );
  }

  const round: CustomAuthRound = {
    userPool,
    user,
    client,
    history: [...session.history],
    clientMetadata: clientMetadata ?? session.clientMetadata,
    postAuthenticationClientMetadata: clientMetadata,
  };

  if (challengeName === "PASSWORD_VERIFIER") {
    if (user.Password === undefined) {
      throw new InvalidPasswordError();
    }
    round.history.push({ challengeName, challengeResult: true });
    return runCustomAuthRound(ctx, services, round);
  }

  if (
    !services.triggers.enabled(
      "VerifyAuthChallengeResponse",
      userPool.options.Id,
    )
  ) {
    throw new UnsupportedError(
      "CUSTOM_CHALLENGE requires VerifyAuthChallengeResponse trigger",
    );
  }

  const verified = await services.triggers.verifyAuthChallengeResponse(ctx, {
    clientId: client.ClientId,
    userAttributes: user.Attributes,
    username: user.Username,
    userPoolId: userPool.options.Id,
    challengeAnswer: challengeResponses.ANSWER ?? "",
    privateChallengeParameters:
      session.pendingChallenge.privateChallengeParameters,
    clientMetadata: round.clientMetadata,
  });

  round.history.push({
    challengeName,
    challengeResult: verified.answerCorrect === true,
    ...(session.pendingChallenge.challengeMetadata !== undefined
      ? { challengeMetadata: session.pendingChallenge.challengeMetadata }
      : {}),
  });

  return runCustomAuthRound(ctx, services, round);
};
