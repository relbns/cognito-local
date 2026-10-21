import type {
  RespondToAuthChallengeRequest,
  RespondToAuthChallengeResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type { Services } from "../services";
import {
  isCustomAuthSession,
  respondToCustomAuthChallenge,
} from "../services/customAuth";
import {
  respondToPhantomChallenge,
  respondToSignInChallenge,
} from "../services/signIn";
import {
  phantomUser,
  preventsUserExistenceErrors,
  unknownUserSignInError,
} from "../services/userExistence";
import type { Target } from "./Target";

export type RespondToAuthChallengeTarget = Target<
  RespondToAuthChallengeRequest,
  RespondToAuthChallengeResponse
>;

type RespondToAuthChallengeService = Pick<
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
> &
  Partial<Pick<Services, "config">>;

export const RespondToAuthChallenge =
  (services: RespondToAuthChallengeService): RespondToAuthChallengeTarget =>
  async (ctx, req) => {
    const { cognito } = services;

    if (!req.ChallengeResponses) {
      throw new InvalidParameterError(
        "Missing required parameter challenge responses",
      );
    }
    if (!req.ChallengeResponses.USERNAME) {
      throw new InvalidParameterError("Missing required parameter USERNAME");
    }
    if (!req.Session && req.ChallengeName !== "PASSWORD_VERIFIER") {
      throw new InvalidParameterError("Missing required parameter Session");
    }

    const userPool = await cognito.getUserPoolForClientId(ctx, req.ClientId);
    const userPoolClient = await cognito.getAppClient(ctx, req.ClientId);

    const user = await userPool.getUserByUsername(
      ctx,
      req.ChallengeResponses.USERNAME,
    );
    if (userPoolClient) {
      services.tokenVerifier.verifySecretHash(
        userPoolClient,
        [req.ChallengeResponses.USERNAME],
        req.ChallengeResponses.SECRET_HASH,
      );
    }
    if (!userPoolClient) {
      throw new NotAuthorizedError();
    }
    if (!user && !preventsUserExistenceErrors(userPoolClient)) {
      throw unknownUserSignInError(userPoolClient);
    }
    const signInUser = user ?? phantomUser(req.ChallengeResponses.USERNAME);

    if (
      req.ChallengeName === "CUSTOM_CHALLENGE" ||
      (req.ChallengeName === "PASSWORD_VERIFIER" &&
        req.Session &&
        isCustomAuthSession(services, req.Session))
    ) {
      return respondToCustomAuthChallenge(ctx, services, {
        userPool,
        user: signInUser,
        userNotFound: !user,
        client: userPoolClient,
        sessionId: req.Session as string,
        challengeName: req.ChallengeName,
        challengeResponses: req.ChallengeResponses,
        clientMetadata: req.ClientMetadata,
      });
    }

    const answer = {
      userPool,
      client: userPoolClient,
      user: signInUser,
      sessionId: req.Session,
      challengeName: req.ChallengeName,
      challengeResponses: req.ChallengeResponses,
      clientMetadata: req.ClientMetadata,
      operation: "respondToAuthChallenge",
    };
    return user
      ? respondToSignInChallenge(ctx, services, answer)
      : respondToPhantomChallenge(services, answer);
  };
