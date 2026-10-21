import { randomBytes } from "node:crypto";
import type { Request, Response } from "express";
import type { Clock } from "../services/clock";

/** Managed login sets a `cognito` cookie that keeps the browser signed in to the user pool. */
export const SESSION_COOKIE = "cognito";

/** Cognito's managed login session cookie is valid for one hour. */
export const DEFAULT_BROWSER_SESSION_SECONDS = 60 * 60;

export interface BrowserSignIn {
  userPoolId: string;
  username: string;
  /** Epoch seconds. */
  authTime: number;
  /** Epoch seconds. */
  expiresAt: number;
}

/**
 * Browser sessions of the hosted pages, in memory. One cookie holds the sign-ins of every user pool,
 * since the emulator serves all pools on one host where Cognito gives each pool its own domain.
 */
export class BrowserSessionStore {
  private readonly sessions = new Map<string, Map<string, BrowserSignIn>>();

  public constructor(
    private readonly clock: Clock,
    private readonly validitySeconds = DEFAULT_BROWSER_SESSION_SECONDS,
  ) {}

  private now(): number {
    return Math.floor(this.clock.get().getTime() / 1000);
  }

  private live(id: string | undefined): Map<string, BrowserSignIn> | null {
    const signIns = id ? this.sessions.get(id) : undefined;
    if (!signIns || !id) return null;
    const now = this.now();
    for (const [poolId, signIn] of signIns) {
      if (signIn.expiresAt <= now) signIns.delete(poolId);
    }
    if (signIns.size === 0) {
      this.sessions.delete(id);
      return null;
    }
    return signIns;
  }

  /** Records a sign-in under a new session id that keeps the browser's other live sign-ins. */
  public signIn(
    previousId: string | undefined,
    userPoolId: string,
    username: string,
  ): string {
    const signIns = new Map(this.live(previousId) ?? []);
    if (previousId) this.sessions.delete(previousId);
    const now = this.now();
    signIns.set(userPoolId, {
      userPoolId,
      username,
      authTime: now,
      expiresAt: now + this.validitySeconds,
    });
    const id = randomBytes(32).toString("base64url");
    this.sessions.set(id, signIns);
    return id;
  }

  public find(
    id: string | undefined,
    userPoolId: string,
  ): BrowserSignIn | null {
    return this.live(id)?.get(userPoolId) ?? null;
  }

  /** Ends the sign-in to one pool; true when the session has no sign-in left. */
  public signOut(id: string | undefined, userPoolId: string): boolean {
    const signIns = this.live(id);
    if (!signIns || !id) return true;
    signIns.delete(userPoolId);
    if (signIns.size > 0) return false;
    this.sessions.delete(id);
    return true;
  }

  public get maxAgeSeconds(): number {
    return this.validitySeconds;
  }
}

export const readSessionCookie = (req: Request): string | undefined => {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const [name, ...value] = part.trim().split("=");
    if (name === SESSION_COOKIE && value.length) {
      return decodeURIComponent(value.join("="));
    }
  }
  return undefined;
};

const cookieOptions = (req: Request) => ({
  httpOnly: true,
  sameSite: "lax" as const,
  secure: req.secure,
  path: "/",
});

/** Signs the browser in to a pool and sets the session cookie; for every hosted page that completes a sign-in. */
export const startBrowserSession = (
  req: Request,
  res: Response,
  store: BrowserSessionStore,
  userPoolId: string,
  username: string,
): void => {
  const id = store.signIn(readSessionCookie(req), userPoolId, username);
  res.cookie(SESSION_COOKIE, id, {
    ...cookieOptions(req),
    maxAge: store.maxAgeSeconds * 1000,
  });
};

/** Signs the browser out of a pool, and drops the cookie when no sign-in is left. */
export const endBrowserSession = (
  req: Request,
  res: Response,
  store: BrowserSessionStore,
  userPoolId: string,
): void => {
  if (store.signOut(readSessionCookie(req), userPoolId)) {
    res.clearCookie(SESSION_COOKIE, cookieOptions(req));
  }
};
