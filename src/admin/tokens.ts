import { createPublicKey, type JsonWebKey } from "node:crypto";
import * as jwt from "jsonwebtoken";

export interface TokenCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export interface TokenInspection {
  header?: Record<string, unknown>;
  payload?: Record<string, unknown>;
  error?: string;
  checks: TokenCheck[];
}

const decodeSegment = (segment: string) => {
  const parsed = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("not a JSON object");
  }
  return parsed as Record<string, unknown>;
};

export const inspectToken = (
  token: string,
  opts: {
    jwks: readonly (JsonWebKey & { kid?: string })[];
    expectedIssuer?: string;
    clientIds?: readonly string[];
    now: Date;
  },
): TokenInspection => {
  const parts = token.trim().split(".");
  if (parts.length !== 3) {
    return { error: "A JWT has three dot-separated parts.", checks: [] };
  }

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = decodeSegment(parts[0]);
    payload = decodeSegment(parts[1]);
  } catch (e) {
    return {
      error: `The token could not be decoded: ${(e as Error).message}`,
      checks: [],
    };
  }

  const checks: TokenCheck[] = [];
  const jwk = opts.jwks.find((key) => key.kid === header.kid);
  checks.push({
    name: "Key id in pool JWKS",
    ok: !!jwk,
    detail: jwk
      ? `kid ${String(header.kid)}`
      : `kid ${String(header.kid)} is not in the pool's JWKS`,
  });

  if (jwk) {
    try {
      jwt.verify(token.trim(), createPublicKey({ key: jwk, format: "jwk" }), {
        algorithms: ["RS256"],
        ignoreExpiration: true,
      });
      checks.push({ name: "Signature", ok: true, detail: "RS256 valid" });
    } catch (e) {
      checks.push({
        name: "Signature",
        ok: false,
        detail: (e as Error).message,
      });
    }
  }

  if (opts.expectedIssuer) {
    checks.push({
      name: "Issuer",
      ok: payload.iss === opts.expectedIssuer,
      detail: `expected ${opts.expectedIssuer}, got ${String(payload.iss)}`,
    });
  }

  if (typeof payload.exp === "number") {
    const expires = new Date(payload.exp * 1000);
    const live = expires.getTime() > opts.now.getTime();
    checks.push({
      name: "Expiry",
      ok: live,
      detail: `${live ? "expires" : "expired"} ${expires.toISOString()}`,
    });
  } else {
    checks.push({ name: "Expiry", ok: false, detail: "no exp claim" });
  }

  const tokenUse = payload.token_use;
  const audience = tokenUse === "id" ? payload.aud : payload.client_id;
  if (opts.clientIds && typeof audience === "string") {
    checks.push({
      name: tokenUse === "id" ? "Audience (aud)" : "Client (client_id)",
      ok: opts.clientIds.includes(audience),
      detail: opts.clientIds.includes(audience)
        ? `${audience} is an app client of this pool`
        : `${audience} is not an app client of this pool`,
    });
  }

  return { header, payload, checks };
};
