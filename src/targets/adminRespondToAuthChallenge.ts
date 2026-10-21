import type {
  AdminRespondToAuthChallengeRequest,
  AdminRespondToAuthChallengeResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type { Services } from "../services";
import {
  isCustomAuthSession,
  respondToCustomAuthChallenge,
} from "../services/customAuth";
import { respondToSignInChallenge } from "../services/signIn";
import type { Target } from "./Target";

export type AdminRespondToAuthChallengeTarget = Target<
  AdminRespondToAuthChallengeRequest,
  AdminRespondToAuthChallengeResponse
>;

type AdminRespondToAuthChallengeServices = Pick<
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

export const AdminRespondToAuthChallenge =
  (
    services: AdminRespondToAuthChallengeServices,
  ): AdminRespondToAuthChallengeTarget =>
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

    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
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
    if (!user || !userPoolClient) {
      throw new NotAuthorizedError();
    }

    if (
      req.ChallengeName === "CUSTOM_CHALLENGE" ||
      (req.ChallengeName === "PASSWORD_VERIFIER" &&
        req.Session &&
        isCustomAuthSession(services, req.Session))
    ) {
      return respondToCustomAuthChallenge(ctx, services, {
        userPool,
        user,
        client: userPoolClient,
        sessionId: req.Session as string,
        challengeName: req.ChallengeName,
        challengeResponses: req.ChallengeResponses,
        clientMetadata: req.ClientMetadata,
      });
    }

    return respondToSignInChallenge(ctx, services, {
      userPool,
      client: userPoolClient,
      user,
      sessionId: req.Session,
      challengeName: req.ChallengeName,
      challengeResponses: req.ChallengeResponses,
      clientMetadata: req.ClientMetadata,
      operation: "adminRespondToAuthChallenge",
    });
  };
