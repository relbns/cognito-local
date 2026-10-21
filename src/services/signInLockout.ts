import { LimitExceededError, NotAuthorizedError } from "../errors";
import type { Config } from "../server/config";
import type { Context } from "./context";
import { INCORRECT_CREDENTIALS } from "./userExistence";
import type { User, UserPoolService } from "./userPoolService";

export const PASSWORD_ATTEMPTS_EXCEEDED = "Password attempts exceeded";
export const ATTEMPT_LIMIT_EXCEEDED =
  "Attempt limit exceeded, please try after some time.";

const FREE_ATTEMPTS = 5;
const MAX_LOCK_SECONDS = 15 * 60;
const QUIET_RESET_MS = 15 * 60_000;
const HOUR_MS = 60 * 60_000;
export const DEFAULT_PASSWORD_RESET_ATTEMPTS_PER_HOUR = 20;

/** Failed password sign-ins of a user, for Cognito's lockout. Epoch milliseconds. */
export interface SignInLockoutState {
  FailedAttempts: number;
  LastAttemptAt: number;
  LockedUntil?: number;
}

type LockoutConfig = Partial<Pick<Config, "LockoutConfig">> | undefined;

const lockoutEnabled = (config: LockoutConfig): boolean =>
  config?.LockoutConfig?.Enabled !== false;

/** Lockout seconds after n failed attempts: 2^(n-5), at most about 15 minutes. */
export const lockoutSeconds = (failedAttempts: number): number =>
  failedAttempts < FREE_ATTEMPTS
    ? 0
    : Math.min(2 ** (failedAttempts - FREE_ATTEMPTS), MAX_LOCK_SECONDS);

/** Throws "Password attempts exceeded" while the user is locked out; such attempts do not count. */
export const assertNotLockedOut = async (
  ctx: Context,
  config: LockoutConfig,
  userPool: UserPoolService,
  user: User,
  now: Date,
): Promise<void> => {
  const state = user.SignInLockout;
  if (!lockoutEnabled(config) || !state?.LockedUntil) return;
  if (now.getTime() >= state.LockedUntil) return;
  await userPool.updateUser(ctx, user, (latest) => ({
    ...latest,
    SignInLockout: latest.SignInLockout && {
      ...latest.SignInLockout,
      LastAttemptAt: now.getTime(),
    },
  }));
  throw new NotAuthorizedError(PASSWORD_ATTEMPTS_EXCEEDED);
};

/** Counts a wrong password and starts or extends the lockout. */
export const recordFailedPassword = async (
  ctx: Context,
  config: LockoutConfig,
  userPool: UserPoolService,
  user: User,
  now: Date,
): Promise<void> => {
  if (!lockoutEnabled(config)) return;
  const at = now.getTime();
  await userPool.updateUser(ctx, user, (latest) => {
    const state = latest.SignInLockout;
    const quietSinceLockout =
      state?.LockedUntil !== undefined &&
      at - state.LastAttemptAt >= QUIET_RESET_MS;
    const failed = (quietSinceLockout ? 0 : (state?.FailedAttempts ?? 0)) + 1;
    const seconds = lockoutSeconds(failed);
    return {
      ...latest,
      SignInLockout: {
        FailedAttempts: failed,
        LastAttemptAt: at,
        ...(seconds ? { LockedUntil: at + seconds * 1000 } : {}),
      },
    };
  });
};

/** A correct password resets the count. */
export const clearFailedPasswords = async (
  ctx: Context,
  userPool: UserPoolService,
  user: User,
): Promise<User> => {
  if (!user.SignInLockout) return user;
  return userPool.updateUser(ctx, user, (latest) => {
    const { SignInLockout: _, ...rest } = latest;
    return rest;
  });
};

/**
 * Counts a ForgotPassword request or ConfirmForgotPassword attempt, refusing it past the hourly limit
 * ("between 5 and 20 attempts" in an hour, managing-users-passwords.html#forgot-password).
 */
export const countPasswordResetAttempt = async (
  ctx: Context,
  config: LockoutConfig,
  userPool: UserPoolService,
  user: User,
  now: Date,
): Promise<User> => {
  const limit =
    config?.LockoutConfig?.PasswordResetAttemptsPerHour ??
    DEFAULT_PASSWORD_RESET_ATTEMPTS_PER_HOUR;
  if (!lockoutEnabled(config) || limit <= 0) return user;
  const at = now.getTime();
  const recent = (user.PasswordResetAttempts ?? []).filter(
    (t) => at - t < HOUR_MS,
  );
  if (recent.length >= limit) {
    throw new LimitExceededError(ATTEMPT_LIMIT_EXCEEDED);
  }
  return userPool.updateUser(ctx, user, (latest) => ({
    ...latest,
    PasswordResetAttempts: [
      ...(latest.PasswordResetAttempts ?? []).filter((t) => at - t < HOUR_MS),
      at,
    ],
  }));
};

/** Runs a password check under the lockout: refuses while locked, counts a wrong password, clears on success. */
export const withPasswordLockout = async <T>(
  ctx: Context,
  config: LockoutConfig,
  userPool: UserPoolService,
  user: User,
  now: Date,
  check: () => T,
): Promise<{ value: T; user: User }> => {
  await assertNotLockedOut(ctx, config, userPool, user, now);
  let value: T;
  try {
    value = check();
  } catch (e) {
    if (
      e instanceof NotAuthorizedError &&
      e.message === INCORRECT_CREDENTIALS
    ) {
      await recordFailedPassword(ctx, config, userPool, user, now);
    }
    throw e;
  }
  return { value, user: await clearFailedPasswords(ctx, userPool, user) };
};

/** Compares a plain password under the lockout and returns the user with the count cleared. */
export const checkPassword = async (
  ctx: Context,
  config: LockoutConfig,
  userPool: UserPoolService,
  user: User,
  password: string | undefined,
  now: Date,
): Promise<User> =>
  (
    await withPasswordLockout(ctx, config, userPool, user, now, () => {
      if (user.Password !== password) {
        throw new NotAuthorizedError(INCORRECT_CREDENTIALS);
      }
    })
  ).user;
