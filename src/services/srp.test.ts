import * as crypto from "node:crypto";
import { describe, expect, it } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { srpClient } from "../__tests__/srpClient";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import {
  InMemorySrpSessions,
  k,
  modPow,
  N,
  padHex,
  passwordClaimSignature,
  passwordVerifier,
  serverPublicValue,
  startPasswordVerifier,
  verifyPasswordClaim,
} from "./srp";

const sha512Hex = (seed: string) =>
  crypto.createHash("sha512").update(seed).digest("hex");

describe("SRP math", () => {
  it("derives the multiplier k = H(PAD(N) | PAD(g)) Cognito clients use", () => {
    expect(k.toString(16)).toEqual(
      "538282c4354742d7cbbde2359fcf67f9f5b3a6b08791e5011b43b8a5b66d9ee6",
    );
  });

  it("pads hex to an even length and prefixes 00 when the high bit is set", () => {
    expect(padHex(BigInt(0xf))).toEqual("0f");
    expect(padHex(BigInt(0x7f))).toEqual("7f");
    expect(padHex(BigInt(0x80))).toEqual("0080");
    expect(padHex(BigInt(0xabc))).toEqual("0abc");
  });

  // Signature produced by amazon-cognito-identity-js 6.3.22 (AuthenticationHelper) for the same inputs.
  it("matches a password claim signature computed by the reference client", () => {
    const poolName = "Ex4mpleP00l";
    const userIdForSrp = "8c1f6a52-3b7e-4d10-9a2e-5f0c7d9e1b44";
    const verifier = passwordVerifier({
      poolName,
      userIdForSrp,
      password: "Example-Passw0rd!",
      salt: "a3f19c2e7b5d4f6081e2c3b4a5968778",
    });
    const a = BigInt(`0x${sha512Hex("client-a").repeat(2)}`);
    const b = BigInt(`0x${sha512Hex("server-b").repeat(2)}`);
    const B = serverPublicValue(verifier, b);

    expect(
      passwordClaimSignature({
        A: modPow(BigInt(2), a, N),
        B,
        b,
        verifier,
        poolName,
        userIdForSrp,
        secretBlock: crypto
          .createHash("sha512")
          .update("secret-block")
          .digest()
          .toString("base64"),
        timestamp: "Wed Oct 21 09:30:05 UTC 2026",
      }),
    ).toEqual("Fy3rqc+R1PsTkEmhgSW5LSPYLlmKekBfPsttZgK804A=");
  });
});

describe("password verifier challenge", () => {
  const userPoolId = "local_Ex4mpleP00l";
  const clientId = "client-id";
  const user = TDB.user({ Password: "Example-Passw0rd!" });

  const start = (sessions: InMemorySrpSessions, srpA: string) =>
    startPasswordVerifier(sessions, { userPoolId, clientId, user, srpA });

  it("accepts the claim of a client that knows the password", () => {
    const sessions = new InMemorySrpSessions(new ClockFake(new Date()));
    for (let i = 0; i < 5; i++) {
      const client = srpClient(userPoolId);
      const challenge = start(sessions, client.srpA);

      expect(challenge.USER_ID_FOR_SRP).toEqual(user.Username);
      expect(() =>
        verifyPasswordClaim(sessions, {
          userPoolId,
          clientId,
          user,
          challengeResponses: client.respond(challenge, "Example-Passw0rd!"),
        }),
      ).not.toThrow();
    }
  });

  it("rejects a wrong password with Cognito's message", () => {
    const sessions = new InMemorySrpSessions(new ClockFake(new Date()));
    const client = srpClient(userPoolId);
    const challenge = start(sessions, client.srpA);

    expect(() =>
      verifyPasswordClaim(sessions, {
        userPoolId,
        clientId,
        user,
        challengeResponses: client.respond(challenge, "wrong-password"),
      }),
    ).toThrow(new NotAuthorizedError("Incorrect username or password."));
  });

  it("rejects every password for a user without one", () => {
    const sessions = new InMemorySrpSessions(new ClockFake(new Date()));
    const noPassword = TDB.user({ Password: "" });
    const client = srpClient(userPoolId);
    const challenge = startPasswordVerifier(sessions, {
      userPoolId,
      clientId,
      user: noPassword,
      srpA: client.srpA,
    });

    expect(() =>
      verifyPasswordClaim(sessions, {
        userPoolId,
        clientId,
        user: noPassword,
        challengeResponses: client.respond(challenge, ""),
      }),
    ).toThrow(new NotAuthorizedError("Incorrect username or password."));
  });

  it("rejects a claim signed with another timestamp", () => {
    const sessions = new InMemorySrpSessions(new ClockFake(new Date()));
    const client = srpClient(userPoolId);
    const challenge = start(sessions, client.srpA);
    const responses = client.respond(challenge, "Example-Passw0rd!");

    expect(() =>
      verifyPasswordClaim(sessions, {
        userPoolId,
        clientId,
        user,
        challengeResponses: {
          ...responses,
          TIMESTAMP: "Wed Oct 21 09:30:06 UTC 2026",
        },
      }),
    ).toThrow(new NotAuthorizedError("Incorrect username or password."));
  });

  it("uses a secret block once", () => {
    const sessions = new InMemorySrpSessions(new ClockFake(new Date()));
    const client = srpClient(userPoolId);
    const challenge = start(sessions, client.srpA);
    const responses = client.respond(challenge, "Example-Passw0rd!");
    verifyPasswordClaim(sessions, {
      userPoolId,
      clientId,
      user,
      challengeResponses: responses,
    });

    expect(() =>
      verifyPasswordClaim(sessions, {
        userPoolId,
        clientId,
        user,
        challengeResponses: responses,
      }),
    ).toThrow(new NotAuthorizedError("Invalid session for the user."));
  });

  it("expires the challenge after the session validity", () => {
    const clock = new ClockFake(new Date());
    const sessions = new InMemorySrpSessions(clock);
    const client = srpClient(userPoolId);
    const challenge = startPasswordVerifier(sessions, {
      userPoolId,
      clientId,
      user,
      srpA: client.srpA,
      validityMinutes: 5,
    });
    clock.advanceBy(5 * 60_000);

    expect(() =>
      verifyPasswordClaim(sessions, {
        userPoolId,
        clientId,
        user,
        challengeResponses: client.respond(challenge, "Example-Passw0rd!"),
      }),
    ).toThrow(
      new NotAuthorizedError(
        "Invalid session for the user, session is expired.",
      ),
    );
  });

  it("rejects a challenge answered through another app client", () => {
    const sessions = new InMemorySrpSessions(new ClockFake(new Date()));
    const client = srpClient(userPoolId);
    const challenge = start(sessions, client.srpA);

    expect(() =>
      verifyPasswordClaim(sessions, {
        userPoolId,
        clientId: "other-client",
        user,
        challengeResponses: client.respond(challenge, "Example-Passw0rd!"),
      }),
    ).toThrow(new NotAuthorizedError("Incorrect username or password."));
  });

  it("rejects SRP_A values that are zero mod N or not hexadecimal", () => {
    const sessions = new InMemorySrpSessions(new ClockFake(new Date()));

    expect(() => start(sessions, N.toString(16))).toThrow(
      InvalidParameterError,
    );
    expect(() => start(sessions, "0")).toThrow(InvalidParameterError);
    expect(() => start(sessions, "not-hex")).toThrow(InvalidParameterError);
  });

  it("requires the three claim parameters", () => {
    const sessions = new InMemorySrpSessions(new ClockFake(new Date()));

    expect(() =>
      verifyPasswordClaim(sessions, {
        userPoolId,
        clientId,
        user,
        challengeResponses: { USERNAME: user.Username },
      }),
    ).toThrow(
      new InvalidParameterError(
        "Missing required parameter PASSWORD_CLAIM_SECRET_BLOCK",
      ),
    );
  });
});
