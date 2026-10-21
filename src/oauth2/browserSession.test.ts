import { describe, expect, it } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { BrowserSessionStore, readSessionCookie } from "./browserSession";

const HOUR = 60 * 60 * 1000;

describe("BrowserSessionStore", () => {
  const start = new Date("2026-01-01T00:00:00Z");

  it("finds a sign-in by pool until it expires", () => {
    const clock = new ClockFake(start);
    const store = new BrowserSessionStore(clock);

    const id = store.signIn(undefined, "pool-a", "jane");

    expect(store.find(id, "pool-a")).toEqual({
      userPoolId: "pool-a",
      username: "jane",
      authTime: start.getTime() / 1000,
      expiresAt: start.getTime() / 1000 + 3600,
    });
    expect(store.find(id, "pool-b")).toBeNull();
    expect(store.find("unknown", "pool-a")).toBeNull();
    expect(store.find(undefined, "pool-a")).toBeNull();

    clock.advanceBy(HOUR - 1000);
    expect(store.find(id, "pool-a")).not.toBeNull();
    clock.advanceBy(1000);
    expect(store.find(id, "pool-a")).toBeNull();
  });

  it("gives a new id on each sign-in and keeps the other pools", () => {
    const store = new BrowserSessionStore(new ClockFake(start));
    const first = store.signIn(undefined, "pool-a", "jane");

    const second = store.signIn(first, "pool-b", "joe");

    expect(second).not.toEqual(first);
    expect(store.find(first, "pool-a")).toBeNull();
    expect(store.find(second, "pool-a")?.username).toBe("jane");
    expect(store.find(second, "pool-b")?.username).toBe("joe");
  });

  it("signs out of one pool and reports when nothing is left", () => {
    const store = new BrowserSessionStore(new ClockFake(start));
    const id = store.signIn(
      store.signIn(undefined, "pool-a", "jane"),
      "pool-b",
      "joe",
    );

    expect(store.signOut(id, "pool-a")).toBe(false);
    expect(store.find(id, "pool-a")).toBeNull();
    expect(store.find(id, "pool-b")).not.toBeNull();
    expect(store.signOut(id, "pool-b")).toBe(true);
    expect(store.signOut(undefined, "pool-b")).toBe(true);
  });

  it("takes another validity", () => {
    const clock = new ClockFake(start);
    const store = new BrowserSessionStore(clock, 60);
    const id = store.signIn(undefined, "pool-a", "jane");

    clock.advanceBy(60_000);

    expect(store.find(id, "pool-a")).toBeNull();
    expect(store.maxAgeSeconds).toBe(60);
  });
});

describe("readSessionCookie", () => {
  const request = (cookie?: string) =>
    ({ headers: cookie ? { cookie } : {} }) as never;

  it("reads the cognito cookie among others", () => {
    expect(readSessionCookie(request("a=1; cognito=abc-123; b=2"))).toBe(
      "abc-123",
    );
    expect(readSessionCookie(request("cognito=a%3Db"))).toBe("a=b");
  });

  it("is undefined without the cookie", () => {
    expect(readSessionCookie(request())).toBeUndefined();
    expect(readSessionCookie(request("cognitox=1; other=2"))).toBeUndefined();
  });
});
