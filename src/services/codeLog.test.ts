import { describe, expect, it } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockMessages } from "../__tests__/mockMessages";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { type AuthSession, InMemoryAuthSessions } from "./authSessions";
import {
  InMemoryCodeLog,
  RecordingAuthSessions,
  RecordingMessages,
} from "./codeLog";

const entry = (username: string) => ({
  type: "SIGN_UP" as const,
  source: "SignUp",
  userPoolId: "pool",
  username,
  code: "123456",
});

const customSession = (history: AuthSession["history"] = []): AuthSession => ({
  userPoolId: "pool",
  clientId: "client",
  username: "otp-user",
  history,
  pendingChallenge: {
    challengeName: "CUSTOM_CHALLENGE",
    privateChallengeParameters: { secretLoginCode: "654321" },
    challengeMetadata: "CODE-654321",
  },
});

describe("InMemoryCodeLog", () => {
  it("lists newest first and keeps only the configured number of entries", () => {
    const clock = new ClockFake(new Date("2026-01-01T00:00:00Z"));
    const log = new InMemoryCodeLog(clock, 2);

    log.record(entry("a"));
    clock.advanceBy(1000);
    log.record(entry("b"));
    clock.advanceBy(1000);
    log.record(entry("c"));

    expect(log.list().map((x) => x.username)).toEqual(["c", "b"]);
    expect(log.list()[0]).toMatchObject({
      id: 3,
      at: new Date("2026-01-01T00:00:02Z"),
    });
  });
});

describe("RecordingMessages", () => {
  it("records the code with its type and delivery, then delivers it", async () => {
    const log = new InMemoryCodeLog(new ClockFake(new Date()));
    const inner = newMockMessages();
    const messages = new RecordingMessages(inner, log);
    const user = TDB.user({
      Username: "jane",
      Attributes: [
        { Name: "email", Value: "jane@example.com" },
        { Name: "phone_number", Value: "+15555550100" },
      ],
    });
    const delivery = {
      AttributeName: "email" as const,
      DeliveryMedium: "EMAIL" as const,
      Destination: "jane@example.com",
    };

    await messages.deliver(
      TestContext,
      "ForgotPassword",
      "client",
      "pool",
      user,
      "111222",
      undefined,
      delivery,
    );

    expect(inner.deliver).toHaveBeenCalledWith(
      TestContext,
      "ForgotPassword",
      "client",
      "pool",
      user,
      "111222",
      undefined,
      delivery,
    );
    expect(log.list()).toEqual([
      expect.objectContaining({
        type: "FORGOT_PASSWORD",
        code: "111222",
        username: "jane",
        email: "jane@example.com",
        phoneNumber: "+15555550100",
        deliveryMedium: "EMAIL",
        destination: "jane@example.com",
      }),
    ]);
  });

  it.each([
    ["SignUp", "SIGN_UP"],
    ["ResendCode", "SIGN_UP"],
    ["Authentication", "MFA"],
    ["AdminCreateUser", "TEMPORARY_PASSWORD"],
    ["UpdateUserAttribute", "ATTRIBUTE_VERIFICATION"],
  ] as const)("maps %s to %s", async (source, type) => {
    const log = new InMemoryCodeLog(new ClockFake(new Date()));
    await new RecordingMessages(newMockMessages(), log).deliver(
      TestContext,
      source,
      null,
      "pool",
      TDB.user(),
      "1",
      undefined,
      { AttributeName: "email", DeliveryMedium: "EMAIL", Destination: "x" },
    );
    expect(log.list()[0].type).toEqual(type);
  });
});

describe("RecordingAuthSessions", () => {
  it("records each CUSTOM_CHALLENGE round with its private parameters and expiry", () => {
    const clock = new ClockFake(new Date("2026-01-01T00:00:00Z"));
    const log = new InMemoryCodeLog(clock);
    const sessions = new RecordingAuthSessions(
      new InMemoryAuthSessions(clock),
      log,
    );

    const id = sessions.create(
      customSession([
        { challengeName: "CUSTOM_CHALLENGE", challengeResult: false },
      ]),
    );

    expect(sessions.peek(id)).toBeDefined();
    expect(sessions.list().map((x) => x.id)).toEqual([id]);
    expect(log.list()).toEqual([
      expect.objectContaining({
        type: "CUSTOM_AUTH",
        username: "otp-user",
        clientId: "client",
        code: "654321",
        round: 2,
        privateChallengeParameters: { secretLoginCode: "654321" },
        expiresAt: new Date("2026-01-01T00:03:00Z"),
      }),
    ]);
  });

  it("does not record PASSWORD_VERIFIER sessions", () => {
    const clock = new ClockFake(new Date());
    const log = new InMemoryCodeLog(clock);
    const sessions = new RecordingAuthSessions(
      new InMemoryAuthSessions(clock),
      log,
    );

    sessions.create({
      ...customSession(),
      pendingChallenge: {
        challengeName: "PASSWORD_VERIFIER",
        privateChallengeParameters: {},
      },
    });

    expect(log.list()).toEqual([]);
  });
});
