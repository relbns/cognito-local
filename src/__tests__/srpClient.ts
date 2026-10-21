import * as crypto from "node:crypto";
import { g, k, modPow, N, padHex } from "../services/srp";

const fromHex = (hex: string) => BigInt(`0x${hex}`);
const sha256Hex = (data: string | Buffer) =>
  crypto.createHash("sha256").update(data).digest("hex");

export const COGNITO_TIMESTAMP = "Wed Oct 21 09:30:05 UTC 2026";

// The client half of Cognito SRP, written from the client's equations: S = (B - k * g^x)^(a + u * x).
export const srpClient = (userPoolId: string, a?: bigint) => {
  const smallA = a ?? fromHex(crypto.randomBytes(128).toString("hex"));
  const A = modPow(g, smallA, N);
  const poolName = userPoolId.split("_")[1] ?? userPoolId;

  return {
    srpA: A.toString(16),
    respond(
      challenge: Record<string, string>,
      password: string,
      timestamp = COGNITO_TIMESTAMP,
    ) {
      const userId = challenge.USER_ID_FOR_SRP;
      const B = fromHex(challenge.SRP_B);
      const u = fromHex(sha256Hex(Buffer.from(padHex(A) + padHex(B), "hex")));
      const x = fromHex(
        sha256Hex(
          Buffer.from(
            padHex(fromHex(challenge.SALT)) +
              sha256Hex(`${poolName}${userId}:${password}`),
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
      const signature = crypto
        .createHmac("sha256", key)
        .update(
          Buffer.concat([
            Buffer.from(poolName, "utf8"),
            Buffer.from(userId, "utf8"),
            Buffer.from(challenge.SECRET_BLOCK, "base64"),
            Buffer.from(timestamp, "utf8"),
          ]),
        )
        .digest("base64");

      return {
        USERNAME: userId,
        PASSWORD_CLAIM_SECRET_BLOCK: challenge.SECRET_BLOCK,
        TIMESTAMP: timestamp,
        PASSWORD_CLAIM_SIGNATURE: signature,
      };
    },
  };
};
