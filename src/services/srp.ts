import * as crypto from "node:crypto";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import { DEFAULT_AUTH_SESSION_VALIDITY_MINUTES } from "./authSessions";
import type { Clock } from "./clock";
import type { User } from "./userPoolService";

// RFC 5054 3072-bit group, the one Cognito and its SRP clients use.
const N_HEX =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
  "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
  "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
  "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
  "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

const ZERO = BigInt(0);
const ONE = BigInt(1);
const TWO = BigInt(2);

export const N = BigInt(`0x${N_HEX}`);
export const g = TWO;

const fromHex = (hex: string): bigint => BigInt(`0x${hex}`);
const sha256Hex = (data: string | Buffer): string =>
  crypto.createHash("sha256").update(data).digest("hex");
const hexHash = (hex: string): string => sha256Hex(Buffer.from(hex, "hex"));

// Shortest even-length hex that reads as a positive two's complement number.
export const padHex = (value: bigint): string => {
  const hex = value.toString(16);
  const even = hex.length % 2 === 1 ? `0${hex}` : hex;
  return /^[89a-f]/.test(even) ? `00${even}` : even;
};

export const modPow = (base: bigint, exponent: bigint, modulus: bigint) => {
  let result = ONE;
  let b = ((base % modulus) + modulus) % modulus;
  let e = exponent;
  while (e > ZERO) {
    if (e & ONE) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= ONE;
  }
  return result;
};

export const k = fromHex(hexHash(padHex(N) + padHex(g)));

export const poolNameOf = (userPoolId: string): string =>
  userPoolId.split("_")[1] ?? userPoolId;

export const passwordVerifier = ({
  poolName,
  userIdForSrp,
  password,
  salt,
}: {
  poolName: string;
  userIdForSrp: string;
  password: string;
  salt: string;
}): bigint => {
  const x = fromHex(
    hexHash(
      padHex(fromHex(salt)) +
        sha256Hex(`${poolName}${userIdForSrp}:${password}`),
    ),
  );
  return modPow(g, x, N);
};

export const serverPublicValue = (verifier: bigint, b: bigint): bigint =>
  (k * verifier + modPow(g, b, N)) % N;

export const passwordClaimSignature = ({
  A,
  B,
  b,
  verifier,
  poolName,
  userIdForSrp,
  secretBlock,
  timestamp,
}: {
  A: bigint;
  B: bigint;
  b: bigint;
  verifier: bigint;
  poolName: string;
  userIdForSrp: string;
  secretBlock: string;
  timestamp: string;
}): string => {
  const u = fromHex(hexHash(padHex(A) + padHex(B)));
  if (u === ZERO) {
    throw new NotAuthorizedError("Incorrect username or password.");
  }
  const S = modPow((A * modPow(verifier, u, N)) % N, b, N);
  const key = Buffer.from(
    crypto.hkdfSync(
      "sha256",
      Buffer.from(padHex(S), "hex"),
      Buffer.from(padHex(u), "hex"),
      "Caldera Derived Key",
      16,
    ),
  );
  return crypto
    .createHmac("sha256", key)
    .update(
      Buffer.concat([
        Buffer.from(poolName, "utf8"),
        Buffer.from(userIdForSrp, "utf8"),
        Buffer.from(secretBlock, "base64"),
        Buffer.from(timestamp, "utf8"),
      ]),
    )
    .digest("base64");
};

export interface SrpChallenge {
  userPoolId: string;
  clientId: string;
  username: string;
  A: bigint;
  b: bigint;
  B: bigint;
  verifier: bigint;
  /** Set for a DEVICE_PASSWORD_VERIFIER challenge, whose identity is the device. */
  device?: { deviceKey: string; deviceGroupKey: string };
  deviceKey?: string;
}

export interface SrpSessions {
  create(challenge: SrpChallenge, validityMinutes?: number): string;
  take(secretBlock: string): SrpChallenge;
}

interface StoredChallenge {
  challenge: SrpChallenge;
  expiresAt: number;
}

// Server state of a PASSWORD_VERIFIER challenge, keyed by the SECRET_BLOCK handed to the client.
export class InMemorySrpSessions implements SrpSessions {
  private readonly challenges = new Map<string, StoredChallenge>();

  public constructor(
    private readonly clock: Clock,
    private readonly validityMinutes = DEFAULT_AUTH_SESSION_VALIDITY_MINUTES,
  ) {}

  public create(challenge: SrpChallenge, validityMinutes?: number): string {
    this.evictExpired();
    const secretBlock = crypto.randomBytes(96).toString("base64");
    const minutes = validityMinutes ?? this.validityMinutes;
    this.challenges.set(secretBlock, {
      challenge,
      expiresAt: this.clock.get().getTime() + minutes * 60_000,
    });
    return secretBlock;
  }

  public take(secretBlock: string): SrpChallenge {
    const stored = this.challenges.get(secretBlock);
    this.challenges.delete(secretBlock);
    if (!stored) {
      throw new NotAuthorizedError("Invalid session for the user.");
    }
    if (stored.expiresAt <= this.clock.get().getTime()) {
      throw new NotAuthorizedError(
        "Invalid session for the user, session is expired.",
      );
    }
    return stored.challenge;
  }

  private evictExpired() {
    const now = this.clock.get().getTime();
    for (const [key, stored] of this.challenges) {
      if (stored.expiresAt <= now) this.challenges.delete(key);
    }
  }
}

// Cognito keeps one salt per password, so the same password gives the same SALT on every sign-in.
const passwordSalt = (
  userPoolId: string,
  username: string,
  password: string,
): string => {
  const bytes = crypto
    .createHash("sha256")
    .update(["password-salt", userPoolId, username, password].join("\u0000"))
    .digest()
    .subarray(0, 16);
  if (bytes[0] === 0) bytes[0] = 1;
  return bytes.toString("hex");
};

const parseSrpA = (srpA: string | undefined): bigint => {
  if (!srpA) {
    throw new InvalidParameterError("Missing required parameter SRP_A");
  }
  if (!/^[0-9a-fA-F]+$/.test(srpA)) {
    throw new InvalidParameterError("SRP_A must be a hexadecimal number");
  }
  const A = fromHex(srpA);
  if (A % N === ZERO) {
    throw new InvalidParameterError("SRP_A mod N cannot be 0");
  }
  return A;
};

const newServerSecret = (verifier: bigint): { b: bigint; B: bigint } => {
  let b: bigint;
  let B: bigint;
  do {
    b = fromHex(crypto.randomBytes(128).toString("hex"));
    B = serverPublicValue(verifier, b);
  } while (B === ZERO);
  return { b, B };
};

export const startPasswordVerifier = (
  srpSessions: SrpSessions,
  {
    userPoolId,
    clientId,
    user,
    srpA,
    validityMinutes,
    deviceKey,
  }: {
    userPoolId: string;
    clientId: string;
    user: User;
    srpA: string | undefined;
    validityMinutes?: number;
    deviceKey?: string;
  },
): Record<string, string> => {
  const A = parseSrpA(srpA);
  // A user without a password, such as a federated one, gets a verifier no password matches.
  const password = user.Password || crypto.randomBytes(32).toString("base64");
  const salt = passwordSalt(userPoolId, user.Username, password);
  const verifier = passwordVerifier({
    poolName: poolNameOf(userPoolId),
    userIdForSrp: user.Username,
    password,
    salt,
  });
  const { b, B } = newServerSecret(verifier);

  const secretBlock = srpSessions.create(
    {
      userPoolId,
      clientId,
      username: user.Username,
      A,
      b,
      B,
      verifier,
      ...(deviceKey ? { deviceKey } : {}),
    },
    validityMinutes,
  );

  return {
    SALT: salt,
    SRP_B: B.toString(16),
    SECRET_BLOCK: secretBlock,
    USER_ID_FOR_SRP: user.Username,
    USERNAME: user.Username,
  };
};

/** A PASSWORD_VERIFIER challenge for a user who does not exist: a stable salt and user id, no usable verifier. */
export const startPhantomPasswordVerifier = (
  srpSessions: SrpSessions,
  {
    userPoolId,
    clientId,
    userIdForSrp,
    salt,
    srpA,
    validityMinutes,
  }: {
    userPoolId: string;
    clientId: string;
    userIdForSrp: string;
    salt: string;
    srpA: string | undefined;
    validityMinutes?: number;
  },
): Record<string, string> => {
  const A = parseSrpA(srpA);
  const verifier = passwordVerifier({
    poolName: poolNameOf(userPoolId),
    userIdForSrp,
    password: crypto.randomBytes(32).toString("base64"),
    salt,
  });
  const { b, B } = newServerSecret(verifier);
  const secretBlock = srpSessions.create(
    { userPoolId, clientId, username: userIdForSrp, A, b, B, verifier },
    validityMinutes,
  );
  return {
    SALT: salt,
    SRP_B: B.toString(16),
    SECRET_BLOCK: secretBlock,
    USER_ID_FOR_SRP: userIdForSrp,
    USERNAME: userIdForSrp,
  };
};

// The device verifier comes from ConfirmDevice: base64 of the hex the client computed.
export const startDeviceVerifier = (
  srpSessions: SrpSessions,
  {
    userPoolId,
    clientId,
    user,
    srpA,
    validityMinutes,
    deviceKey,
    deviceGroupKey,
    passwordVerifier: verifierBase64,
    salt: saltBase64,
  }: {
    userPoolId: string;
    clientId: string;
    user: User;
    srpA: string | undefined;
    validityMinutes?: number;
    deviceKey: string;
    deviceGroupKey: string;
    passwordVerifier: string;
    salt: string;
  },
): Record<string, string> => {
  const A = parseSrpA(srpA);
  const verifier = fromHex(
    Buffer.from(verifierBase64, "base64").toString("hex") || "0",
  );
  const salt = Buffer.from(saltBase64, "base64").toString("hex");
  const { b, B } = newServerSecret(verifier);

  const secretBlock = srpSessions.create(
    {
      userPoolId,
      clientId,
      username: user.Username,
      A,
      b,
      B,
      verifier,
      device: { deviceKey, deviceGroupKey },
    },
    validityMinutes,
  );

  return {
    SALT: salt,
    SRP_B: B.toString(16),
    SECRET_BLOCK: secretBlock,
    USERNAME: user.Username,
  };
};

const requireClaimParameters = (challengeResponses: Record<string, string>) => {
  for (const name of [
    "PASSWORD_CLAIM_SECRET_BLOCK",
    "PASSWORD_CLAIM_SIGNATURE",
    "TIMESTAMP",
  ]) {
    if (!challengeResponses[name]) {
      throw new InvalidParameterError(`Missing required parameter ${name}`);
    }
  }
};

const assertSignature = (
  challenge: SrpChallenge,
  challengeResponses: Record<string, string>,
  poolName: string,
  userIdForSrp: string,
) => {
  const expected = Buffer.from(
    passwordClaimSignature({
      A: challenge.A,
      B: challenge.B,
      b: challenge.b,
      verifier: challenge.verifier,
      poolName,
      userIdForSrp,
      secretBlock: challengeResponses.PASSWORD_CLAIM_SECRET_BLOCK,
      timestamp: challengeResponses.TIMESTAMP,
    }),
    "base64",
  );
  const actual = Buffer.from(
    challengeResponses.PASSWORD_CLAIM_SIGNATURE,
    "base64",
  );
  if (
    actual.length !== expected.length ||
    !crypto.timingSafeEqual(actual, expected)
  ) {
    throw new NotAuthorizedError("Incorrect username or password.");
  }
};

export const verifyDeviceClaim = (
  srpSessions: SrpSessions,
  {
    userPoolId,
    clientId,
    user,
    challengeResponses,
  }: {
    userPoolId: string;
    clientId: string;
    user: User;
    challengeResponses: Record<string, string>;
  },
): { deviceKey: string } => {
  requireClaimParameters(challengeResponses);
  const challenge = srpSessions.take(
    challengeResponses.PASSWORD_CLAIM_SECRET_BLOCK,
  );
  if (
    !challenge.device ||
    challenge.userPoolId !== userPoolId ||
    challenge.clientId !== clientId ||
    challenge.username !== user.Username ||
    (challengeResponses.DEVICE_KEY &&
      challengeResponses.DEVICE_KEY !== challenge.device.deviceKey)
  ) {
    throw new NotAuthorizedError("Incorrect username or password.");
  }
  assertSignature(
    challenge,
    challengeResponses,
    challenge.device.deviceGroupKey,
    challenge.device.deviceKey,
  );
  return { deviceKey: challenge.device.deviceKey };
};

export const verifyPasswordClaim = (
  srpSessions: SrpSessions,
  {
    userPoolId,
    clientId,
    user,
    challengeResponses,
  }: {
    userPoolId: string;
    clientId: string;
    user: User;
    challengeResponses: Record<string, string>;
  },
): { deviceKey?: string } => {
  requireClaimParameters(challengeResponses);
  const challenge = srpSessions.take(
    challengeResponses.PASSWORD_CLAIM_SECRET_BLOCK,
  );
  if (
    challenge.device ||
    challenge.userPoolId !== userPoolId ||
    challenge.clientId !== clientId ||
    challenge.username !== user.Username
  ) {
    throw new NotAuthorizedError("Incorrect username or password.");
  }
  assertSignature(
    challenge,
    challengeResponses,
    poolNameOf(userPoolId),
    challenge.username,
  );
  return { deviceKey: challengeResponses.DEVICE_KEY || challenge.deviceKey };
};
