import {
  InvalidParameterError,
  LimitExceededError,
  NotAuthorizedError,
  WebAuthnChallengeNotFoundError,
  WebAuthnClientMismatchError,
  WebAuthnConfigurationMissingError,
  WebAuthnNotEnabledError,
  WebAuthnRelyingPartyMismatchError,
} from "../errors";
import type { Clock } from "./clock";
import type { Context } from "./context";
import { isMfaRequired } from "./mfa";
import type { User, UserPool, UserPoolService } from "./userPoolService";
import {
  assertionCredentialId,
  credentialCreationOptions,
  credentialRequestOptions,
  friendlyCredentialName,
  MAX_WEBAUTHN_CREDENTIALS,
  newChallenge,
  passkeyMfaConfigured,
  REGISTRATION_CHALLENGE_VALIDITY_MS,
  relyingPartyId,
  userHandle,
  userVerification,
  verifyAssertion,
  verifyRegistration,
  type WebAuthnCredential,
  webAuthnEnabled,
} from "./webAuthn";

const requireRelyingPartyId = (pool: UserPool): string => {
  if (!webAuthnEnabled(pool)) throw new WebAuthnNotEnabledError();
  const rpId = relyingPartyId(pool);
  if (!rpId) throw new WebAuthnConfigurationMissingError();
  return rpId;
};

const assertBelowLimit = (user: User) => {
  if ((user.WebAuthnCredentials ?? []).length >= MAX_WEBAUTHN_CREDENTIALS) {
    throw new LimitExceededError(
      `A user can register at most ${MAX_WEBAUTHN_CREDENTIALS} passkeys.`,
    );
  }
};

/** StartWebAuthnRegistration: a new challenge on the user record and the options for navigator.credentials.create. */
export const startPasskeyRegistration = async (
  ctx: Context,
  params: {
    userPool: UserPoolService;
    user: User;
    clientId: string;
    clock: Clock;
  },
) => {
  const pool = params.userPool.options;
  const rpId = requireRelyingPartyId(pool);
  assertBelowLimit(params.user);
  const challenge = newChallenge();
  const updated = await params.userPool.updateUser(
    ctx,
    params.user,
    (latest) => ({
      ...latest,
      WebAuthnRegistration: {
        Challenge: challenge,
        ClientId: params.clientId,
        RelyingPartyId: rpId,
        ExpiresAt:
          params.clock.get().getTime() + REGISTRATION_CHALLENGE_VALIDITY_MS,
      },
    }),
  );
  return credentialCreationOptions(pool, updated, rpId, challenge);
};

/** CompleteWebAuthnRegistration: verifies the attestation and stores the credential. */
export const completePasskeyRegistration = async (
  ctx: Context,
  params: {
    userPool: UserPoolService;
    user: User;
    clientId: string;
    credential: unknown;
    clock: Clock;
  },
): Promise<WebAuthnCredential> => {
  const pool = params.userPool.options;
  const rpId = requireRelyingPartyId(pool);
  const pending = params.user.WebAuthnRegistration;
  const now = params.clock.get();
  if (!pending || pending.ExpiresAt <= now.getTime()) {
    throw new WebAuthnChallengeNotFoundError();
  }
  if (pending.ClientId !== params.clientId) {
    throw new WebAuthnClientMismatchError();
  }
  if (pending.RelyingPartyId !== rpId) {
    throw new WebAuthnRelyingPartyMismatchError();
  }
  if (params.credential === undefined || params.credential === null) {
    throw new InvalidParameterError("Missing required parameter Credential");
  }
  assertBelowLimit(params.user);

  const verified = verifyRegistration({
    credential: params.credential,
    expectedChallenge: pending.Challenge,
    rpId,
    requireUserVerification: userVerification(pool) === "required",
  });
  if (
    (params.user.WebAuthnCredentials ?? []).some(
      (c) => c.CredentialId === verified.credentialId,
    )
  ) {
    throw new InvalidParameterError("The passkey is already registered.");
  }

  const credential: WebAuthnCredential = {
    CredentialId: verified.credentialId,
    PublicKey: verified.publicKey,
    Algorithm: verified.algorithm,
    SignCount: verified.signCount,
    RelyingPartyId: rpId,
    FriendlyCredentialName: friendlyCredentialName(
      verified.authenticatorAttachment,
    ),
    AuthenticatorAttachment: verified.authenticatorAttachment,
    AuthenticatorTransports: verified.transports,
    CreatedDate: now,
  };
  await params.userPool.updateUser(ctx, params.user, (latest) => ({
    ...latest,
    WebAuthnCredentials: [...(latest.WebAuthnCredentials ?? []), credential],
    WebAuthnRegistration: undefined,
    UserLastModifiedDate: now,
  }));
  return credential;
};

/** Passkeys of the user that the pool's current relying party can use. */
export const usablePasskeys = (
  pool: UserPool,
  user: User,
): WebAuthnCredential[] => {
  const rpId = relyingPartyId(pool);
  return rpId
    ? (user.WebAuthnCredentials ?? []).filter((c) => c.RelyingPartyId === rpId)
    : [];
};

/** Passkey MFA lets a verified passkey sign in a user who must otherwise pass MFA. */
export const passkeySatisfiesMfa = (pool: UserPool, user: User): boolean =>
  passkeyMfaConfigured(pool) && !!user.WebAuthnMfaEnabled;

/** Whether USER_AUTH (and the hosted login page) can offer WEB_AUTHN to this user. */
export const passkeySignInAvailable = (pool: UserPool, user: User): boolean =>
  webAuthnEnabled(pool) &&
  usablePasskeys(pool, user).length > 0 &&
  (!isMfaRequired(pool, user) || passkeySatisfiesMfa(pool, user));

export interface PasskeyChallenge {
  challenge: string;
  requireUserVerification: boolean;
  options: ReturnType<typeof credentialRequestOptions>;
}

export const newPasskeyChallenge = (
  pool: UserPool,
  user: User,
): PasskeyChallenge => {
  const rpId = relyingPartyId(pool);
  if (!rpId) throw new WebAuthnConfigurationMissingError();
  const challenge = newChallenge();
  const requireUserVerification =
    userVerification(pool) === "required" ||
    (isMfaRequired(pool, user) && passkeySatisfiesMfa(pool, user));
  return {
    challenge,
    requireUserVerification,
    options: credentialRequestOptions(
      rpId,
      challenge,
      usablePasskeys(pool, user),
      requireUserVerification ? "required" : "preferred",
    ),
  };
};

/**
 * Verifies a passkey assertion for the user and records the new signature counter.
 * Returns the updated user and whether the passkey also satisfies MFA.
 */
export const verifyPasskeySignIn = async (
  ctx: Context,
  params: {
    userPool: UserPoolService;
    user: User;
    credential: string | undefined;
    challenge: string | undefined;
    requireUserVerification: boolean;
    clock: Clock;
  },
): Promise<{ user: User; satisfiesMfa: boolean }> => {
  if (!params.credential) {
    throw new InvalidParameterError("Missing required parameter CREDENTIAL");
  }
  const pool = params.userPool.options;
  const rpId = relyingPartyId(pool);
  const id = assertionCredentialId(params.credential);
  const stored = usablePasskeys(pool, params.user).find(
    (c) => c.CredentialId === id,
  );
  if (!rpId || !stored || !params.challenge) {
    throw new NotAuthorizedError("Incorrect username or password.");
  }
  const result = verifyAssertion({
    credential: params.credential,
    expectedChallenge: params.challenge,
    rpId,
    stored,
    requireUserVerification: params.requireUserVerification,
    expectedUserHandle: userHandle(params.user),
  });
  const now = params.clock.get();
  const user = await params.userPool.updateUser(ctx, params.user, (latest) => ({
    ...latest,
    WebAuthnCredentials: (latest.WebAuthnCredentials ?? []).map((c) =>
      c.CredentialId === id
        ? { ...c, SignCount: result.signCount, LastAuthenticatedDate: now }
        : c,
    ),
  }));
  return {
    user,
    satisfiesMfa:
      result.userVerified &&
      isMfaRequired(pool, params.user) &&
      passkeySatisfiesMfa(pool, params.user),
  };
};

/** The user's passkey MFA flag after a (Admin)SetUserMFAPreference request with WebAuthnMfaSettings. */
export const passkeyMfaPreference = (
  pool: UserPool,
  settings: { Enabled?: boolean } | undefined,
  current: boolean | undefined,
  otherMfaMethods: readonly string[],
): boolean | undefined => {
  if (settings?.Enabled === undefined) return current;
  if (!settings.Enabled) return false;
  if (!passkeyMfaConfigured(pool)) {
    throw new InvalidParameterError(
      "Passkey MFA needs FactorConfiguration MULTI_FACTOR_WITH_USER_VERIFICATION in the user pool's WebAuthnConfiguration.",
    );
  }
  if (otherMfaMethods.length === 0) {
    throw new InvalidParameterError(
      "Passkey MFA needs another MFA method enabled for the user.",
    );
  }
  return true;
};
