import { describe, expect, it } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { NotAuthorizedError } from "../errors";
import { type AuthSession, InMemoryAuthSessions } from "./authSessions";

const session: AuthSession = {
  userPoolId: "pool",
  clientId: "client",
  username: "user",
  history: [],
  pendingChallenge: {
    challengeName: "CUSTOM_CHALLENGE",
    privateChallengeParameters: { secretLoginCode: "123456" },
  },
};

describe("InMemoryAuthSessions", () => {
  it("returns a stored session once", () => {
    const sessions = new InMemoryAuthSessions(new ClockFake(new Date()));
    const id = sessions.create(session);

    expect(sessions.take(id)).toEqual(session);
    expect(() => sessions.take(id)).toThrow(
      new NotAuthorizedError("Invalid session for the user."),
    );
  });

  it("expires sessions after three minutes by default", () => {
    const clock = new ClockFake(new Date());
    const sessions = new InMemoryAuthSessions(clock);
    const id = sessions.create(session);

    clock.advanceBy(3 * 60_000 - 1);
    expect(sessions.peek(id)).toEqual(session);

    clock.advanceBy(1);
    expect(sessions.peek(id)).toBeUndefined();
    expect(() => sessions.take(id)).toThrow(
      new NotAuthorizedError(
        "Invalid session for the user, session is expired.",
      ),
    );
  });

  it("honours a configured validity", () => {
    const clock = new ClockFake(new Date());
    const sessions = new InMemoryAuthSessions(clock, 15);
    const id = sessions.create(session);

    clock.advanceBy(14 * 60_000);
    expect(sessions.take(id)).toEqual(session);
  });

  it("lists active sessions newest first and drops expired ones", () => {
    const clock = new ClockFake(new Date("2026-01-01T00:00:00Z"));
    const sessions = new InMemoryAuthSessions(clock);
    const first = sessions.create(session);
    clock.advanceBy(60_000);
    const second = sessions.create({ ...session, username: "other" });

    expect(sessions.list().map((x) => x.id)).toEqual([second, first]);
    expect(sessions.list()[0].expiresAt).toEqual(
      new Date("2026-01-01T00:04:00Z"),
    );

    clock.advanceBy(2 * 60_000);
    expect(sessions.list().map((x) => x.id)).toEqual([second]);
  });
});
