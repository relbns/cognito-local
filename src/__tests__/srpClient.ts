import * as crypto from "node:crypto";
import { g, k, modPow, N, padHex } from "../services/srp";

const fromHex = (hex: string) => BigInt(`0x${hex}`);
const sha256Hex = (data: string | Buffer) =>
  crypto.createHash("sha256").update(data).digest("hex");

export const COGNITO_TIMESTAMP = "Wed Oct 21 09:30:05 UTC 2026";

const randomA = () => fromHex(crypto.randomBytes(128).toString("hex"));

// The client half of Cognito SRP, written from the client's equations: S = (B - k * g^x)^(a + u * x).
const claimSignature = ({
  smallA,
  challenge,
  realm,
  identity,
  password,
  timestamp,
}: {
  smallA: bigint;
  challenge: Record<string, string>;
  realm: string;
  identity: string;
  password: string;
  timestamp: string;
}) => {
  const A = modPow(g, smallA, N);
  const B = fromHex(challenge.SRP_B);
  const u = fromHex(sha256Hex(Buffer.from(padHex(A) + padHex(B), "hex")));
  const x = fromHex(
    sha256Hex(
      Buffer.from(
        padHex(fromHex(challenge.SALT)) +
          sha256Hex(`${realm}${identity}:${password}`),
        "hex",
      ),
    ),
  );
  const S = modPow(B - k * modPow(g, x, N), smallA + u * x, N);
  const prk = crypto
    .createHmac("sha256", Buffer.from(padHex(u), "hex"))
    .update(Buffer.from(padHex(S), "hex"))
    .digest();
  const key = crypto
    .createHmac("sha256", prk)
    .update(Buffer.from("Caldera Derived Key\u0001", "utf8"))
    .digest()
    .subarray(0, 16);
  return crypto
    .createHmac("sha256", key)
    .update(
      Buffer.concat([
        Buffer.from(realm, "utf8"),
        Buffer.from(identity, "utf8"),
        Buffer.from(challenge.SECRET_BLOCK, "base64"),
        Buffer.from(timestamp, "utf8"),
      ]),
    )
    .digest("base64");
};

export const srpClient = (userPoolId: string, a?: bigint) => {
  const smallA = a ?? randomA();
  const poolName = userPoolId.split("_")[1] ?? userPoolId;

  return {
    srpA: modPow(g, smallA, N).toString(16),
    respond(
      challenge: Record<string, string>,
      password: string,
      timestamp = COGNITO_TIMESTAMP,
    ) {
      const userId = challenge.USER_ID_FOR_SRP;
      return {
        USERNAME: userId,
        PASSWORD_CLAIM_SECRET_BLOCK: challenge.SECRET_BLOCK,
        TIMESTAMP: timestamp,
        PASSWORD_CLAIM_SIGNATURE: claimSignature({
          smallA,
          challenge,
          realm: poolName,
          identity: userId,
          password,
          timestamp,
        }),
      };
    },
  };
};

/** The secret a client keeps for a remembered device and the verifier it sends in ConfirmDevice. */
export const deviceSecret = (deviceGroupKey: string, deviceKey: string) => {
  const devicePassword = crypto.randomBytes(40).toString("base64");
  const saltHex = padHex(fromHex(crypto.randomBytes(16).toString("hex")));
  const x = fromHex(
    sha256Hex(
      Buffer.from(
        saltHex + sha256Hex(`${deviceGroupKey}${deviceKey}:${devicePassword}`),
        "hex",
      ),
    ),
  );
  return {
    devicePassword,
    verifierConfig: {
      PasswordVerifier: Buffer.from(padHex(modPow(g, x, N)), "hex").toString(
        "base64",
      ),
      Salt: Buffer.from(saltHex, "hex").toString("base64"),
    },
  };
};

export const deviceSrpClient = (
  username: string,
  deviceGroupKey: string,
  deviceKey: string,
  devicePassword: string,
) => {
  const smallA = randomA();
  return {
    srpA: modPow(g, smallA, N).toString(16),
    respond(challenge: Record<string, string>, timestamp = COGNITO_TIMESTAMP) {
      return {
        USERNAME: username,
        DEVICE_KEY: deviceKey,
        PASSWORD_CLAIM_SECRET_BLOCK: challenge.SECRET_BLOCK,
        TIMESTAMP: timestamp,
        PASSWORD_CLAIM_SIGNATURE: claimSignature({
          smallA,
          challenge,
          realm: deviceGroupKey,
          identity: deviceKey,
          password: devicePassword,
          timestamp,
        }),
      };
    },
  };
};
