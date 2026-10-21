import { v4 } from "uuid";
import { NotAuthorizedError } from "../errors";
import type { Clock } from "./clock";

export const DEFAULT_AUTH_SESSION_VALIDITY_MINUTES = 3;

export interface ChallengeResult {
  challengeName: string;
  challengeResult: boolean;
  challengeMetadata?: string;
}

export interface PendingChallenge {
  challengeName: string;
  privateChallengeParameters: Record<string, string>;
  challengeMetadata?: string;
}

/** State of a built-in sign-in challenge; custom authentication sessions leave it unset. */
export interface SignInState {
  deviceKey?: string;
  availableChallenges?: string[];
  code?: string;
  totpSecret?: string;
  totpVerified?: boolean;
  webAuthnChallenge?: string;
  webAuthnRequireUserVerification?: boolean;
  tokenSource?: "Authentication" | "NewPasswordChallenge";
  /** A simulated challenge for a user who does not exist (PreventUserExistenceErrors ENABLED). */
  phantom?: boolean;
}

export interface AuthSession {
  userPoolId: string;
  clientId: string;
  username: string;
  clientMetadata?: Record<string, string>;
  history: ChallengeResult[];
  srpA?: string;
  pendingChallenge: PendingChallenge;
  signIn?: SignInState;
  /** A custom authentication session for a user who does not exist. */
  userNotFound?: boolean;
}

export interface ActiveAuthSession {
  id: string;
  expiresAt: Date;
  session: AuthSession;
}

export interface AuthSessions {
  create(session: AuthSession, validityMinutes?: number): string;
  list(): ActiveAuthSession[];
  peek(sessionId: string): AuthSession | undefined;
  take(sessionId: string): AuthSession;
}

interface StoredSession {
  session: AuthSession;
  expiresAt: number;
}

export class InMemoryAuthSessions implements AuthSessions {
  private readonly sessions = new Map<string, StoredSession>();

  public constructor(
    private readonly clock: Clock,
    private readonly validityMinutes = DEFAULT_AUTH_SESSION_VALIDITY_MINUTES,
  ) {}

  public create(session: AuthSession, validityMinutes?: number): string {
    this.evictExpired();
    const id = v4();
    const minutes = validityMinutes ?? this.validityMinutes;
    this.sessions.set(id, {
      session,
      expiresAt: this.clock.get().getTime() + minutes * 60_000,
    });
    return id;
  }

  public list(): ActiveAuthSession[] {
    this.evictExpired();
    return [...this.sessions.entries()]
      .map(([id, stored]) => ({
        id,
        expiresAt: new Date(stored.expiresAt),
        session: stored.session,
      }))
      .sort((a, b) => b.expiresAt.getTime() - a.expiresAt.getTime());
  }

  public peek(sessionId: string): AuthSession | undefined {
    const stored = this.sessions.get(sessionId);
    if (!stored || stored.expiresAt <= this.clock.get().getTime()) {
      return undefined;
    }
    return stored.session;
  }

  public take(sessionId: string): AuthSession {
    const stored = this.sessions.get(sessionId);
    this.sessions.delete(sessionId);
    if (!stored) {
      throw new NotAuthorizedError("Invalid session for the user.");
    }
    if (stored.expiresAt <= this.clock.get().getTime()) {
      throw new NotAuthorizedError(
        "Invalid session for the user, session is expired.",
      );
    }
    return stored.session;
  }

  private evictExpired() {
    const now = this.clock.get().getTime();
    for (const [id, stored] of this.sessions) {
      if (stored.expiresAt <= now) this.sessions.delete(id);
    }
  }
}
