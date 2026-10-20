import * as jwt from "jsonwebtoken";
import { describe, expect, it } from "vitest";
import PrivateKey from "../keys/cognitoLocal.private.json";
import PublicKey from "../keys/cognitoLocal.public.json";
import { inspectToken } from "./tokens";

const now = new Date("2026-01-01T00:00:00Z");
const issuer = "http://localhost:9229/local_pool";

const sign = (claims: object, opts: jwt.SignOptions = {}) =>
  jwt.sign(
    {
      iat: Math.floor(now.getTime() / 1000),
      exp: Math.floor(now.getTime() / 1000) + 3600,
      ...claims,
    },
    PrivateKey.pem,
    { algorithm: "RS256", keyid: "CognitoLocal", issuer, ...opts },
  );

const inspect = (token: string) =>
  inspectToken(token, {
    jwks: [PublicKey.jwk],
    expectedIssuer: issuer,
    clientIds: ["client-1"],
    now,
  });

const failed = (result: ReturnType<typeof inspect>) =>
  result.checks.filter((c) => !c.ok).map((c) => c.name);

describe("inspectToken", () => {
  it("decodes and passes every check for an emulator-issued access token", () => {
    const result = inspect(
      sign({ token_use: "access", client_id: "client-1", sub: "abc" }),
    );

    expect(result.header).toMatchObject({ alg: "RS256", kid: "CognitoLocal" });
    expect(result.payload).toMatchObject({ sub: "abc", iss: issuer });
    expect(failed(result)).toEqual([]);
    expect(result.checks.map((c) => c.name)).toEqual([
      "Key id in pool JWKS",
      "Signature",
      "Issuer",
      "Expiry",
      "Client (client_id)",
    ]);
  });

  it("checks the audience of an id token", () => {
    const result = inspect(sign({ token_use: "id", aud: "other-client" }));
    expect(failed(result)).toEqual(["Audience (aud)"]);
  });

  it("fails the signature of a tampered token", () => {
    const [h, , s] = sign({ token_use: "access", client_id: "client-1" }).split(
      ".",
    );
    const payload = Buffer.from(
      JSON.stringify({
        token_use: "access",
        client_id: "client-1",
        iss: issuer,
        exp: 9999999999,
      }),
    ).toString("base64url");
    expect(failed(inspect(`${h}.${payload}.${s}`))).toEqual(["Signature"]);
  });

  it("reports an expired token, a foreign issuer and an unknown key id", () => {
    const expired = inspect(
      sign(
        { token_use: "access", client_id: "client-1", exp: 1 },
        { issuer: "http://elsewhere/pool" },
      ),
    );
    expect(failed(expired)).toEqual(["Issuer", "Expiry"]);

    const unknownKey = inspect(
      sign({ token_use: "access", client_id: "client-1" }, { keyid: "nope" }),
    );
    expect(failed(unknownKey)).toEqual(["Key id in pool JWKS"]);
  });

  it("returns an error for input that is not a JWT", () => {
    expect(inspect("not-a-token").error).toMatch(/three dot-separated parts/);
    expect(inspect("a.b.c").error).toMatch(/could not be decoded/);
  });
});
