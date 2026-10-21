import { NotAuthorizedError } from "../errors";
import type { AppClient } from "./appClient";
import type { AuthSessions } from "./authSessions";

export const SIGN_UP_STEP = "SIGN_UP";
export const SIGN_UP_CONFIRMED_STEP = "SIGN_UP_CONFIRMED";

/** SignUp and ConfirmSignUp return a Session for clients that allow USER_AUTH. */
export const userAuthAllowed = (client: AppClient | null | undefined) =>
  !!client?.ExplicitAuthFlows?.includes("ALLOW_USER_AUTH");

export const createSignUpSession = (
  authSessions: AuthSessions,
  client: AppClient,
  username: string,
  step: typeof SIGN_UP_STEP | typeof SIGN_UP_CONFIRMED_STEP,
): string =>
  authSessions.create(
    {
      userPoolId: client.UserPoolId,
      clientId: client.ClientId,
      username,
      history: [],
      pendingChallenge: { challengeName: step, privateChallengeParameters: {} },
      signIn: {},
    },
    client.AuthSessionValidity,
  );

/** Uses up a Session from ConfirmSignUp, which signs the confirmed user in (InitiateAuth Session). */
export const takeSignUpConfirmedSession = (
  authSessions: AuthSessions,
  sessionId: string,
  client: AppClient,
  username: string,
): void => {
  const session = authSessions.take(sessionId);
  if (
    session.pendingChallenge.challengeName !== SIGN_UP_CONFIRMED_STEP ||
    session.clientId !== client.ClientId ||
    session.userPoolId !== client.UserPoolId ||
    session.username !== username
  ) {
    throw new NotAuthorizedError("Invalid session for the user.");
  }
};

/** Drops the SignUp Session that ConfirmSignUp received, when it belongs to that user. */
export const consumeSignUpSession = (
  authSessions: AuthSessions,
  sessionId: string | undefined,
  client: AppClient,
  username: string,
): void => {
  if (!sessionId) return;
  const session = authSessions.peek(sessionId);
  if (
    session?.pendingChallenge.challengeName === SIGN_UP_STEP &&
    session.clientId === client.ClientId &&
    session.username === username
  ) {
    authSessions.take(sessionId);
  }
};
