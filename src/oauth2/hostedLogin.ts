import {
  CodeMismatchError,
  CognitoError,
  InvalidParameterError,
  InvalidPasswordError,
  NotAuthorizedError,
} from "../errors";
import type { Services, UserPoolService } from "../services";
import type { AppClient } from "../services/appClient";
import type { Context } from "../services/context";
import { type MfaMethod, smsMfaDelivery } from "../services/mfa";
import {
  completeTotpSetup,
  newTotpSecret,
  nextMfaStep,
  totpUri,
} from "../services/mfaSetup";
import {
  newPasskeyChallenge,
  passkeySignInAvailable,
  verifyPasskeySignIn,
} from "../services/passkeys";
import { assertPasswordConformsToPolicy } from "../services/passwordPolicy";
import { verify as verifyTotp } from "../services/totp";
import { runPreAuthentication } from "../services/triggers/preAuthentication";
import type { User } from "../services/userPoolService";
import type {
  HostedLoginStep,
  HostedLoginStore,
  PendingHostedLogin,
} from "./hostedLoginStore";
import type { AuthorizeFlow } from "./oauthRequest";

export const HOSTED_LOGIN_MESSAGES = {
  incorrectCredentials: "Incorrect username or password.",
  userDisabled: "User is disabled.",
  passwordResetRequired: "Password reset required for the user.",
  newPasswordRequired: "Enter a new password.",
  passwordsDoNotMatch: "Passwords do not match.",
  chooseMfaMethod: "Choose a sign-in method.",
  codeMismatch: "Invalid code or auth state for the user.",
  sessionExpired: "Invalid session for the user, session is expired.",
  mfaSetupRequired:
    "This user must set up MFA before signing in. Set it up through the API (AssociateSoftwareToken, VerifySoftwareToken, SetUserMFAPreference).",
  smsDestinationMissing:
    "SMS MFA is enabled but the user has no phone number to send the code to.",
  usernameRequired: "Enter your username to sign in with a passkey.",
  passkeyUnavailable: "Passkey sign-in is not available for this user.",
  passkeyFailed: "The passkey could not be verified. Try again.",
} as const;

export type HostedLoginServices = Pick<
  Services,
  "clock" | "config" | "messages" | "otp" | "triggers"
>;

export interface HostedLoginContext {
  userPool: UserPoolService;
  appClient: AppClient;
  redirectUri: string;
  state: string | undefined;
  scope: string;
  flow: AuthorizeFlow;
}

export type HostedLoginOutcome =
  | { kind: "loginError"; error: string }
  | { kind: "step"; sessionId: string; step: HostedLoginStep; error?: string }
  | { kind: "signedIn"; user: User }
  | { kind: "loginNotice"; notice: string };

export type HostedLoginForm = Partial<
  Record<
    "new_password" | "confirm_password" | "mfa_method" | "code" | "credential",
    string
  >
>;

const loginError = (error: string): HostedLoginOutcome => ({
  kind: "loginError",
  error,
});

const toStep = (
  store: HostedLoginStore,
  login: HostedLoginContext,
  user: User,
  step: HostedLoginStep,
): HostedLoginOutcome => {
  const pending: PendingHostedLogin = {
    userPoolId: login.userPool.options.Id,
    clientId: login.appClient.ClientId,
    username: user.Username,
    redirectUri: login.redirectUri,
    state: login.state,
    scope: login.scope,
    flow: login.flow,
    step,
  };
  return { kind: "step", sessionId: store.create(pending), step };
};

async function completeSignIn(
  ctx: Context,
  services: HostedLoginServices,
  login: HostedLoginContext,
  user: User,
): Promise<HostedLoginOutcome> {
  const userPoolId = login.userPool.options.Id;
  if (!services.triggers.enabled("PostAuthentication", userPoolId)) {
    return { kind: "signedIn", user };
  }
  await services.triggers.postAuthentication(ctx, {
    clientId: login.appClient.ClientId,
    clientMetadata: undefined,
    source: "PostAuthentication_Authentication",
    userAttributes: user.Attributes,
    username: user.Username,
    userPoolId,
  });
  // The trigger can change the user through the admin API, so tokens come from the stored record.
  const reloaded = await login.userPool.getUserByUsername(ctx, user.Username);
  return { kind: "signedIn", user: reloaded ?? user };
}

async function startMfaMethod(
  ctx: Context,
  services: HostedLoginServices,
  store: HostedLoginStore,
  login: HostedLoginContext,
  user: User,
  method: MfaMethod,
): Promise<HostedLoginOutcome> {
  if (method === "SOFTWARE_TOKEN_MFA") {
    return toStep(store, login, user, { kind: "totpMfa" });
  }
  const delivery = smsMfaDelivery(user);
  if (!delivery) return loginError(HOSTED_LOGIN_MESSAGES.smsDestinationMissing);
  const code = services.otp();
  await services.messages.deliver(
    ctx,
    "Authentication",
    login.appClient.ClientId,
    login.userPool.options.Id,
    user,
    code,
    undefined,
    delivery,
  );
  return toStep(store, login, user, {
    kind: "smsMfa",
    code,
    destination: delivery.Destination,
  });
}

const mfaSetupStep = (
  login: HostedLoginContext,
  user: User,
): HostedLoginStep => {
  const secret = newTotpSecret();
  return {
    kind: "mfaSetup",
    secret,
    uri: totpUri(login.userPool.options, user, secret),
  };
};

async function afterPassword(
  ctx: Context,
  services: HostedLoginServices,
  store: HostedLoginStore,
  login: HostedLoginContext,
  user: User,
): Promise<HostedLoginOutcome> {
  const next = nextMfaStep(login.userPool.options, user);
  switch (next.kind) {
    case "none":
      return completeSignIn(ctx, services, login, user);
    case "challenge":
      return startMfaMethod(ctx, services, store, login, user, next.method);
    case "select":
      return toStep(store, login, user, {
        kind: "selectMfa",
        methods: next.methods,
      });
    case "setup":
      // An SMS factor needs a phone number, which this page does not collect.
      if (!next.options.includes("SOFTWARE_TOKEN_MFA")) {
        return loginError(HOSTED_LOGIN_MESSAGES.smsDestinationMissing);
      }
      return toStep(store, login, user, mfaSetupStep(login, user));
    case "unavailable":
      return loginError(HOSTED_LOGIN_MESSAGES.mfaSetupRequired);
  }
}

async function findOrMigrateUser(
  ctx: Context,
  services: HostedLoginServices,
  login: HostedLoginContext,
  username: string,
  password: string,
): Promise<User | null> {
  const userPoolId = login.userPool.options.Id;
  const user = await login.userPool.getUserByUsername(ctx, username);
  if (user || !services.triggers.enabled("UserMigration", userPoolId)) {
    return user;
  }
  try {
    return await services.triggers.userMigration(ctx, {
      clientId: login.appClient.ClientId,
      clientMetadata: undefined,
      password,
      userAttributes: [],
      username,
      userPoolId,
      validationData: undefined,
    });
  } catch (e) {
    if (e instanceof NotAuthorizedError) return null;
    throw e;
  }
}

export async function signInWithPassword(
  ctx: Context,
  services: HostedLoginServices,
  store: HostedLoginStore,
  login: HostedLoginContext,
  username: string,
  password: string,
): Promise<HostedLoginOutcome> {
  const user = await findOrMigrateUser(
    ctx,
    services,
    login,
    username,
    password,
  );
  try {
    await runPreAuthentication(ctx, services.triggers, {
      client: login.appClient,
      user,
      username,
      userPoolId: login.userPool.options.Id,
      validationData: undefined,
    });
  } catch (e) {
    if (e instanceof CognitoError) return loginError(e.message);
    throw e;
  }
  if (!user) return loginError(HOSTED_LOGIN_MESSAGES.incorrectCredentials);
  if (user.UserStatus === "RESET_REQUIRED") {
    return loginError(HOSTED_LOGIN_MESSAGES.passwordResetRequired);
  }
  if (user.Password !== password) {
    return loginError(HOSTED_LOGIN_MESSAGES.incorrectCredentials);
  }
  if (!user.Enabled) return loginError(HOSTED_LOGIN_MESSAGES.userDisabled);
  if (user.UserStatus === "UNCONFIRMED") {
    return loginError(HOSTED_LOGIN_MESSAGES.incorrectCredentials);
  }
  if (user.UserStatus === "FORCE_CHANGE_PASSWORD") {
    return toStep(store, login, user, { kind: "newPassword" });
  }
  return afterPassword(ctx, services, store, login, user);
}

/** Starts passkey sign-in for a username, as the managed login page does before it prompts for the passkey. */
export async function signInWithPasskey(
  ctx: Context,
  services: HostedLoginServices,
  store: HostedLoginStore,
  login: HostedLoginContext,
  username: string,
): Promise<HostedLoginOutcome> {
  if (!username) return loginError(HOSTED_LOGIN_MESSAGES.usernameRequired);
  const user = await login.userPool.getUserByUsername(ctx, username);
  try {
    await runPreAuthentication(ctx, services.triggers, {
      client: login.appClient,
      user,
      username,
      userPoolId: login.userPool.options.Id,
      validationData: undefined,
    });
  } catch (e) {
    if (e instanceof CognitoError) return loginError(e.message);
    throw e;
  }
  if (!user || !passkeySignInAvailable(login.userPool.options, user)) {
    return loginError(HOSTED_LOGIN_MESSAGES.passkeyUnavailable);
  }
  if (!user.Enabled) return loginError(HOSTED_LOGIN_MESSAGES.userDisabled);
  if (user.UserStatus === "RESET_REQUIRED") {
    return loginError(HOSTED_LOGIN_MESSAGES.passwordResetRequired);
  }
  const passkey = newPasskeyChallenge(login.userPool.options, user);
  return toStep(store, login, user, {
    kind: "passkey",
    challenge: passkey.challenge,
    requireUserVerification: passkey.requireUserVerification,
    options: passkey.options,
  });
}

/** Signs in a user who has just signed up and confirmed in this browser, as managed login does after sign-up. */
export async function signInAfterSignUp(
  ctx: Context,
  services: HostedLoginServices,
  store: HostedLoginStore,
  login: HostedLoginContext,
  user: User,
): Promise<HostedLoginOutcome> {
  try {
    await runPreAuthentication(ctx, services.triggers, {
      client: login.appClient,
      user,
      username: user.Username,
      userPoolId: login.userPool.options.Id,
      validationData: undefined,
    });
  } catch (e) {
    if (e instanceof CognitoError) return loginError(e.message);
    throw e;
  }
  if (!user.Enabled) return loginError(HOSTED_LOGIN_MESSAGES.userDisabled);
  return afterPassword(ctx, services, store, login, user);
}

export async function continueHostedLogin(
  ctx: Context,
  services: HostedLoginServices,
  store: HostedLoginStore,
  login: HostedLoginContext,
  sessionId: string,
  pending: PendingHostedLogin,
  form: HostedLoginForm,
): Promise<HostedLoginOutcome> {
  const user = await login.userPool.getUserByUsername(ctx, pending.username);
  if (!user || !user.Enabled) {
    store.delete(sessionId);
    return loginError(
      user
        ? HOSTED_LOGIN_MESSAGES.userDisabled
        : HOSTED_LOGIN_MESSAGES.incorrectCredentials,
    );
  }
  const retry = (error: string): HostedLoginOutcome => ({
    kind: "step",
    sessionId,
    step: pending.step,
    error,
  });
  const step = pending.step;

  switch (step.kind) {
    case "newPassword": {
      const newPassword = form.new_password ?? "";
      if (!newPassword) return retry(HOSTED_LOGIN_MESSAGES.newPasswordRequired);
      if (
        form.confirm_password !== undefined &&
        form.confirm_password !== newPassword
      ) {
        return retry(HOSTED_LOGIN_MESSAGES.passwordsDoNotMatch);
      }
      try {
        assertPasswordConformsToPolicy(
          services.config,
          login.userPool.options,
          newPassword,
        );
      } catch (e) {
        if (e instanceof InvalidPasswordError) return retry(e.message);
        throw e;
      }
      store.delete(sessionId);
      const updated = await login.userPool.updateUser(ctx, user, (latest) => ({
        ...latest,
        Password: newPassword,
        UserStatus: "CONFIRMED",
        UserLastModifiedDate: services.clock.get(),
      }));
      return afterPassword(ctx, services, store, login, updated);
    }
    case "selectMfa": {
      const method = step.methods.find((m) => m === form.mfa_method);
      if (!method) return retry(HOSTED_LOGIN_MESSAGES.chooseMfaMethod);
      store.delete(sessionId);
      return startMfaMethod(ctx, services, store, login, user, method);
    }
    case "smsMfa": {
      if (form.code?.trim() !== step.code) {
        return retry(HOSTED_LOGIN_MESSAGES.codeMismatch);
      }
      store.delete(sessionId);
      return completeSignIn(ctx, services, login, user);
    }
    case "totpMfa": {
      const code = form.code?.trim();
      const totp = user.SoftwareTokenMfaConfiguration;
      if (!code || !totp?.Verified || !verifyTotp(totp.Secret, code)) {
        return retry(HOSTED_LOGIN_MESSAGES.codeMismatch);
      }
      store.delete(sessionId);
      return completeSignIn(ctx, services, login, user);
    }
    case "mfaSetup": {
      const code = form.code?.trim();
      if (!code) return retry(HOSTED_LOGIN_MESSAGES.codeMismatch);
      let registered: User;
      try {
        registered = await completeTotpSetup(ctx, {
          userPool: login.userPool,
          user,
          secret: step.secret,
          code,
          clock: services.clock,
        });
      } catch (e) {
        if (e instanceof CodeMismatchError) {
          return retry(HOSTED_LOGIN_MESSAGES.codeMismatch);
        }
        throw e;
      }
      store.delete(sessionId);
      return completeSignIn(ctx, services, login, registered);
    }
    case "passkey": {
      let verified: Awaited<ReturnType<typeof verifyPasskeySignIn>>;
      try {
        verified = await verifyPasskeySignIn(ctx, {
          userPool: login.userPool,
          user,
          credential: form.credential,
          challenge: step.challenge,
          requireUserVerification: step.requireUserVerification,
          clock: services.clock,
        });
      } catch (e) {
        if (
          e instanceof NotAuthorizedError ||
          e instanceof InvalidParameterError
        ) {
          return retry(HOSTED_LOGIN_MESSAGES.passkeyFailed);
        }
        throw e;
      }
      store.delete(sessionId);
      return verified.satisfiesMfa
        ? completeSignIn(ctx, services, login, verified.user)
        : afterPassword(ctx, services, store, login, verified.user);
    }
    case "confirmSignUp":
    case "confirmForgotPassword":
      store.delete(sessionId);
      return loginError(HOSTED_LOGIN_MESSAGES.sessionExpired);
  }
}
