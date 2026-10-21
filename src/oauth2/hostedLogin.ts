import {
  CognitoError,
  InvalidPasswordError,
  NotAuthorizedError,
} from "../errors";
import type { Services, UserPoolService } from "../services";
import type { AppClient } from "../services/appClient";
import type { Context } from "../services/context";
import {
  enabledMfaMethods,
  isMfaRequired,
  type MfaMethod,
  smsMfaDelivery,
} from "../services/mfa";
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
  | { kind: "signedIn"; user: User };

export type HostedLoginForm = Partial<
  Record<"new_password" | "confirm_password" | "mfa_method" | "code", string>
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

async function afterPassword(
  ctx: Context,
  services: HostedLoginServices,
  store: HostedLoginStore,
  login: HostedLoginContext,
  user: User,
): Promise<HostedLoginOutcome> {
  if (!isMfaRequired(login.userPool.options, user)) {
    return completeSignIn(ctx, services, login, user);
  }
  const methods = enabledMfaMethods(user);
  if (methods.length === 0) {
    return loginError(HOSTED_LOGIN_MESSAGES.mfaSetupRequired);
  }
  const preferred = methods.find((m) => m === user.PreferredMfaSetting);
  if (!preferred && methods.length > 1) {
    return toStep(store, login, user, { kind: "selectMfa", methods });
  }
  return startMfaMethod(
    ctx,
    services,
    store,
    login,
    user,
    preferred ?? methods[0],
  );
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
  }
}
