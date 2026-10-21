import * as crypto from "node:crypto";
import {
  InvalidParameterError,
  NotAuthorizedError,
  WebAuthnChallengeNotFoundError,
  WebAuthnCredentialNotSupportedError,
  WebAuthnOriginNotAllowedError,
  WebAuthnRelyingPartyMismatchError,
} from "../errors";
import { CborError, type CborValue, decodeCbor, decodeCborFirst } from "./cbor";
import { attributeValue, type User, type UserPool } from "./userPoolService";

export const ES256 = -7;
export const RS256 = -257;
const SUPPORTED_ALGORITHMS = [ES256, RS256];

export const MAX_WEBAUTHN_CREDENTIALS = 20;
export const REGISTRATION_TIMEOUT_MS = 60_000;
export const REGISTRATION_CHALLENGE_VALIDITY_MS = 5 * 60_000;
export const AUTHENTICATION_TIMEOUT_MS = 180_000;

export interface WebAuthnCredential {
  CredentialId: string;
  /** COSE_Key of the credential, base64url. */
  PublicKey: string;
  Algorithm: number;
  SignCount: number;
  RelyingPartyId: string;
  FriendlyCredentialName: string;
  AuthenticatorAttachment?: string;
  AuthenticatorTransports: string[];
  CreatedDate: Date;
  LastAuthenticatedDate?: Date;
}

export interface WebAuthnRegistrationChallenge {
  Challenge: string;
  ClientId: string;
  RelyingPartyId: string;
  /** Epoch milliseconds. */
  ExpiresAt: number;
}

type UserVerification = "required" | "preferred";

export const webAuthnEnabled = (pool: UserPool): boolean =>
  (pool.Policies?.SignInPolicy?.AllowedFirstAuthFactors ?? []).includes(
    "WEB_AUTHN",
  );

/** WebAuthnConfiguration.RelyingPartyId, else the custom domain, else the prefix domain. */
export const relyingPartyId = (pool: UserPool): string | undefined => {
  const configured = pool.WebAuthnConfiguration?.RelyingPartyId;
  if (configured) return configured;
  if (pool.CustomDomain) return pool.CustomDomain;
  if (pool.Domain) {
    const region = pool.Id.split("_")[0];
    return `${pool.Domain}.auth.${region}.amazoncognito.com`;
  }
  return undefined;
};

export const userVerification = (pool: UserPool): UserVerification =>
  pool.WebAuthnConfiguration?.UserVerification === "required"
    ? "required"
    : "preferred";

/** A stored WebAuthnConfiguration as GetUserPoolMfaConfig reports it, with the defaults filled in. */
export const webAuthnConfigurationResponse = (
  config: UserPool["WebAuthnConfiguration"],
): UserPool["WebAuthnConfiguration"] =>
  config && {
    ...(config.RelyingPartyId ? { RelyingPartyId: config.RelyingPartyId } : {}),
    UserVerification: config.UserVerification ?? "preferred",
    FactorConfiguration: config.FactorConfiguration ?? "SINGLE_FACTOR",
  };

export const passkeyMfaConfigured = (pool: UserPool): boolean =>
  pool.WebAuthnConfiguration?.FactorConfiguration ===
  "MULTI_FACTOR_WITH_USER_VERIFICATION";

export const userHandle = (user: User): string =>
  Buffer.from(
    attributeValue("sub", user.Attributes) ?? user.Username,
    "utf8",
  ).toString("base64url");

export const newChallenge = (): string =>
  crypto.randomBytes(32).toString("base64url");

export const credentialDescription = (credential: WebAuthnCredential) => ({
  CredentialId: credential.CredentialId,
  FriendlyCredentialName: credential.FriendlyCredentialName,
  RelyingPartyId: credential.RelyingPartyId,
  AuthenticatorAttachment: credential.AuthenticatorAttachment,
  AuthenticatorTransports: credential.AuthenticatorTransports,
  CreatedAt: credential.CreatedDate,
});

export const credentialCreationOptions = (
  pool: UserPool,
  user: User,
  rpId: string,
  challenge: string,
) => ({
  hints: [],
  attestation: "none",
  attestationFormats: [],
  rp: { id: rpId, name: rpId },
  user: {
    id: userHandle(user),
    name: user.Username,
    displayName: attributeValue("name", user.Attributes) ?? "",
  },
  challenge,
  pubKeyCredParams: SUPPORTED_ALGORITHMS.map((alg) => ({
    type: "public-key",
    alg,
  })),
  timeout: REGISTRATION_TIMEOUT_MS,
  excludeCredentials: (user.WebAuthnCredentials ?? []).map((c) => ({
    type: "public-key",
    id: c.CredentialId,
  })),
  authenticatorSelection: {
    requireResidentKey: true,
    residentKey: "required",
    userVerification: userVerification(pool),
  },
});

export const credentialRequestOptions = (
  rpId: string,
  challenge: string,
  credentials: readonly WebAuthnCredential[],
  verification: UserVerification,
) => ({
  hints: [],
  attestation: "none",
  attestationFormats: [],
  challenge,
  timeout: AUTHENTICATION_TIMEOUT_MS,
  rpId,
  allowCredentials: credentials.map((c) => ({
    id: c.CredentialId,
    type: "public-key",
  })),
  userVerification: verification,
});

/** Same-site origins of the RP ID; plain http only on localhost; Android app origins as given. */
export const isOriginAllowed = (origin: string, rpId: string): boolean => {
  if (origin.startsWith("android:apk-key-hash:")) return true;
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  const host = url.hostname.toLowerCase();
  const rp = rpId.toLowerCase();
  if (host !== rp && !host.endsWith(`.${rp}`)) return false;
  if (url.protocol === "https:") return true;
  return (
    url.protocol === "http:" &&
    (host === "localhost" || host.endsWith(".localhost"))
  );
};

interface AuthenticatorFlags {
  userPresent: boolean;
  userVerified: boolean;
  attestedCredentialData: boolean;
}

interface AttestedCredential {
  credentialId: Buffer;
  publicKey: Buffer;
  coseKey: Map<CborValue, CborValue>;
}

export interface AuthenticatorData {
  rpIdHash: Buffer;
  flags: AuthenticatorFlags;
  signCount: number;
  attested?: AttestedCredential;
}

export const parseAuthenticatorData = (data: Buffer): AuthenticatorData => {
  if (data.length < 37) throw new CborError("authenticatorData is too short");
  const flagsByte = data.readUInt8(32);
  const flags = {
    userPresent: (flagsByte & 0x01) !== 0,
    userVerified: (flagsByte & 0x04) !== 0,
    attestedCredentialData: (flagsByte & 0x40) !== 0,
  };
  const result: AuthenticatorData = {
    rpIdHash: data.subarray(0, 32),
    flags,
    signCount: data.readUInt32BE(33),
  };
  if (!flags.attestedCredentialData) return result;

  if (data.length < 55) throw new CborError("attestedCredentialData is short");
  const idLength = data.readUInt16BE(53);
  const keyStart = 55 + idLength;
  if (keyStart > data.length) throw new CborError("credentialId is truncated");
  const { value, end } = decodeCborFirst(data, keyStart);
  if (!(value instanceof Map)) throw new CborError("COSE key is not a map");
  result.attested = {
    credentialId: data.subarray(55, keyStart),
    publicKey: data.subarray(keyStart, end),
    coseKey: value,
  };
  return result;
};

const coseBytes = (key: Map<CborValue, CborValue>, label: number): string => {
  const value = key.get(label);
  if (!Buffer.isBuffer(value)) {
    throw new WebAuthnCredentialNotSupportedError("Malformed public key");
  }
  return value.toString("base64url");
};

/** A node public key from an ES256 (EC2 P-256) or RS256 (RSA) COSE_Key. */
export const cosePublicKey = (
  key: Map<CborValue, CborValue>,
): { key: crypto.KeyObject; algorithm: number } => {
  const kty = key.get(1);
  const alg = key.get(3);
  if (alg === ES256 && kty === 2 && key.get(-1) === 1) {
    return {
      algorithm: ES256,
      key: crypto.createPublicKey({
        format: "jwk",
        key: {
          kty: "EC",
          crv: "P-256",
          x: coseBytes(key, -2),
          y: coseBytes(key, -3),
        },
      }),
    };
  }
  if (alg === RS256 && kty === 3) {
    return {
      algorithm: RS256,
      key: crypto.createPublicKey({
        format: "jwk",
        key: { kty: "RSA", n: coseBytes(key, -1), e: coseBytes(key, -2) },
      }),
    };
  }
  throw new WebAuthnCredentialNotSupportedError(
    "Passkeys must use the ES256 or RS256 algorithm.",
  );
};

const verifySignature = (
  algorithm: number,
  key: crypto.KeyObject,
  data: Buffer,
  signature: Buffer,
): boolean => {
  try {
    return algorithm === ES256
      ? crypto.verify("sha256", data, { key, dsaEncoding: "der" }, signature)
      : crypto.verify("sha256", data, key, signature);
  } catch {
    return false;
  }
};

const sha256 = (data: Buffer | string): Buffer =>
  crypto.createHash("sha256").update(data).digest();

const asRecord = (value: unknown): Record<string, unknown> | undefined =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;

const parseCredential = (credential: unknown): Record<string, unknown> => {
  let parsed = credential;
  if (typeof credential === "string") {
    try {
      parsed = JSON.parse(credential);
    } catch {
      throw new InvalidParameterError("The credential is not valid JSON.");
    }
  }
  const record = asRecord(parsed);
  if (!record || !asRecord(record.response)) {
    throw new InvalidParameterError("The credential has no response.");
  }
  return record;
};

const base64urlField = (
  record: Record<string, unknown>,
  name: string,
): Buffer => {
  const value = record[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new InvalidParameterError(`The credential has no ${name}.`);
  }
  return Buffer.from(value, "base64url");
};

interface ClientData {
  type: string;
  challenge: string;
  origin: string;
}

const parseClientData = (clientDataJSON: Buffer): ClientData => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(clientDataJSON.toString("utf8"));
  } catch {
    throw new InvalidParameterError("clientDataJSON is not valid JSON.");
  }
  const record = asRecord(parsed);
  if (
    !record ||
    typeof record.type !== "string" ||
    typeof record.challenge !== "string" ||
    typeof record.origin !== "string"
  ) {
    throw new InvalidParameterError("clientDataJSON is incomplete.");
  }
  return record as unknown as ClientData;
};

const sameChallenge = (received: string, expected: string): boolean => {
  const a = Buffer.from(received, "base64url");
  const b = Buffer.from(expected, "base64url");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

export interface VerifiedRegistration {
  credentialId: string;
  publicKey: string;
  algorithm: number;
  signCount: number;
  transports: string[];
  authenticatorAttachment?: string;
  attestationFormat: string;
}

const verifyPackedAttestation = (
  statement: Map<CborValue, CborValue>,
  signedData: Buffer,
  credentialKey: { key: crypto.KeyObject; algorithm: number },
): void => {
  const alg = statement.get("alg");
  const sig = statement.get("sig");
  const x5c = statement.get("x5c");
  if (typeof alg !== "number" || !Buffer.isBuffer(sig)) {
    throw new InvalidParameterError("The packed attestation is malformed.");
  }
  if (Array.isArray(x5c) && x5c.length > 0 && Buffer.isBuffer(x5c[0])) {
    if (!SUPPORTED_ALGORITHMS.includes(alg)) {
      throw new WebAuthnCredentialNotSupportedError(
        "The attestation algorithm is not supported.",
      );
    }
    const certificate = new crypto.X509Certificate(x5c[0]);
    if (!verifySignature(alg, certificate.publicKey, signedData, sig)) {
      throw new InvalidParameterError("The attestation signature is invalid.");
    }
    return;
  }
  if (alg !== credentialKey.algorithm) {
    throw new InvalidParameterError(
      "The self attestation algorithm does not match the credential.",
    );
  }
  if (!verifySignature(alg, credentialKey.key, signedData, sig)) {
    throw new InvalidParameterError("The attestation signature is invalid.");
  }
};

/** Checks a RegistrationResponseJSON against the challenge and relying party, as CompleteWebAuthnRegistration does. */
export const verifyRegistration = (input: {
  credential: unknown;
  expectedChallenge: string;
  rpId: string;
  requireUserVerification: boolean;
}): VerifiedRegistration => {
  const credential = parseCredential(input.credential);
  const response = asRecord(credential.response) as Record<string, unknown>;
  if (credential.type !== undefined && credential.type !== "public-key") {
    throw new InvalidParameterError("The credential type must be public-key.");
  }
  const clientDataJSON = base64urlField(response, "clientDataJSON");
  const clientData = parseClientData(clientDataJSON);
  if (clientData.type !== "webauthn.create") {
    throw new InvalidParameterError(
      "clientDataJSON.type must be webauthn.create.",
    );
  }
  if (!sameChallenge(clientData.challenge, input.expectedChallenge)) {
    throw new WebAuthnChallengeNotFoundError();
  }
  if (!isOriginAllowed(clientData.origin, input.rpId)) {
    throw new WebAuthnOriginNotAllowedError(clientData.origin);
  }

  let attestation: CborValue;
  let authData: AuthenticatorData;
  try {
    attestation = decodeCbor(base64urlField(response, "attestationObject"));
    if (!(attestation instanceof Map)) throw new CborError("not a map");
    const raw = attestation.get("authData");
    if (!Buffer.isBuffer(raw)) throw new CborError("no authData");
    authData = parseAuthenticatorData(raw);
  } catch (e) {
    if (e instanceof CborError) {
      throw new InvalidParameterError("The attestationObject is malformed.");
    }
    throw e;
  }
  const attestationMap = attestation as Map<CborValue, CborValue>;
  const rawAuthData = attestationMap.get("authData") as Buffer;

  if (!authData.rpIdHash.equals(sha256(input.rpId))) {
    throw new WebAuthnRelyingPartyMismatchError();
  }
  if (!authData.flags.userPresent) {
    throw new InvalidParameterError(
      "The authenticator did not test user presence.",
    );
  }
  if (input.requireUserVerification && !authData.flags.userVerified) {
    throw new WebAuthnCredentialNotSupportedError(
      "The user pool requires an authenticator that verifies the user.",
    );
  }
  if (!authData.attested) {
    throw new InvalidParameterError(
      "The authenticator returned no credential.",
    );
  }
  const credentialId = authData.attested.credentialId.toString("base64url");
  const declaredId = credential.rawId ?? credential.id;
  if (
    typeof declaredId === "string" &&
    !Buffer.from(declaredId, "base64url").equals(authData.attested.credentialId)
  ) {
    throw new InvalidParameterError(
      "The credential id does not match the authenticator data.",
    );
  }
  const credentialKey = cosePublicKey(authData.attested.coseKey);

  const format = attestationMap.get("fmt");
  const statement = attestationMap.get("attStmt");
  if (typeof format !== "string" || !(statement instanceof Map)) {
    throw new InvalidParameterError("The attestationObject is malformed.");
  }
  const signedData = Buffer.concat([rawAuthData, sha256(clientDataJSON)]);
  if (format === "none") {
    if (statement.size !== 0) {
      throw new InvalidParameterError("A none attestation has no statement.");
    }
  } else if (format === "packed") {
    verifyPackedAttestation(statement, signedData, credentialKey);
  }

  const transports = Array.isArray(response.transports)
    ? response.transports.filter((t): t is string => typeof t === "string")
    : [];
  const attachment =
    typeof credential.authenticatorAttachment === "string"
      ? credential.authenticatorAttachment
      : undefined;

  return {
    credentialId,
    publicKey: authData.attested.publicKey.toString("base64url"),
    algorithm: credentialKey.algorithm,
    signCount: authData.signCount,
    transports,
    authenticatorAttachment: attachment,
    attestationFormat: format,
  };
};

/** The credential id an AuthenticationResponseJSON names, normalised to base64url. */
export const assertionCredentialId = (credential: unknown): string => {
  const record = parseCredential(credential);
  const id = record.rawId ?? record.id;
  if (typeof id !== "string" || id.length === 0) {
    throw new InvalidParameterError("The credential has no id.");
  }
  return Buffer.from(id, "base64url").toString("base64url");
};

/** Checks an AuthenticationResponseJSON against a stored credential; returns the new signature counter. */
export const verifyAssertion = (input: {
  credential: unknown;
  expectedChallenge: string;
  rpId: string;
  stored: WebAuthnCredential;
  requireUserVerification: boolean;
  expectedUserHandle: string;
}): { signCount: number; userVerified: boolean } => {
  const credential = parseCredential(input.credential);
  const response = asRecord(credential.response) as Record<string, unknown>;
  const clientDataJSON = base64urlField(response, "clientDataJSON");
  const rawAuthData = base64urlField(response, "authenticatorData");
  const signature = base64urlField(response, "signature");
  const clientData = parseClientData(clientDataJSON);

  const refuse = (): never => {
    throw new NotAuthorizedError("Incorrect username or password.");
  };
  if (clientData.type !== "webauthn.get") refuse();
  if (!sameChallenge(clientData.challenge, input.expectedChallenge)) refuse();
  if (!isOriginAllowed(clientData.origin, input.rpId)) refuse();
  if (input.stored.RelyingPartyId !== input.rpId) refuse();

  let authData: AuthenticatorData;
  try {
    authData = parseAuthenticatorData(rawAuthData);
  } catch {
    throw new InvalidParameterError("authenticatorData is malformed.");
  }
  if (!authData.rpIdHash.equals(sha256(input.rpId))) refuse();
  if (!authData.flags.userPresent) refuse();
  if (input.requireUserVerification && !authData.flags.userVerified) refuse();

  if (
    typeof response.userHandle === "string" &&
    response.userHandle.length > 0 &&
    !Buffer.from(response.userHandle, "base64url").equals(
      Buffer.from(input.expectedUserHandle, "base64url"),
    )
  ) {
    refuse();
  }

  const coseKey = decodeCbor(Buffer.from(input.stored.PublicKey, "base64url"));
  const { key, algorithm } = cosePublicKey(
    coseKey as Map<CborValue, CborValue>,
  );
  const signedData = Buffer.concat([rawAuthData, sha256(clientDataJSON)]);
  if (!verifySignature(algorithm, key, signedData, signature)) refuse();

  // A counter that does not grow means a cloned authenticator; zero means the authenticator keeps none.
  const previous = input.stored.SignCount;
  if (
    (authData.signCount !== 0 || previous !== 0) &&
    authData.signCount <= previous
  ) {
    refuse();
  }

  return {
    signCount: authData.signCount,
    userVerified: authData.flags.userVerified,
  };
};

export const friendlyCredentialName = (attachment: string | undefined) =>
  attachment === "platform"
    ? "Platform authenticator"
    : attachment === "cross-platform"
      ? "Security key"
      : "Passkey";
