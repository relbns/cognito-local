import { randomBytes } from "node:crypto";
import { DEFAULT_AUTH_SESSION_VALIDITY_MINUTES } from "../services/authSessions";
import type { Clock } from "../services/clock";
import type { MfaMethod } from "../services/mfa";
import type { AuthorizeFlow } from "./oauthRequest";

export type HostedLoginStep =
  | { kind: "newPassword" }
  | { kind: "selectMfa"; methods: readonly MfaMethod[] }
  | { kind: "smsMfa"; code: string; destination: string }
  | { kind: "totpMfa" };

export interface PendingHostedLogin {
  userPoolId: string;
  clientId: string;
  username: string;
  redirectUri: string;
  state: string | undefined;
  scope: string;
  flow: AuthorizeFlow;
  step: HostedLoginStep;
}

interface Entry {
  login: PendingHostedLogin;
  expiresAt: number;
}

export class HostedLoginStore {
  private readonly pending = new Map<string, Entry>();

  public constructor(
    private readonly clock: Clock,
    private readonly validityMs = DEFAULT_AUTH_SESSION_VALIDITY_MINUTES *
      60_000,
  ) {}

  public create(login: PendingHostedLogin): string {
    const now = this.clock.get().getTime();
    for (const [id, entry] of this.pending) {
      if (entry.expiresAt <= now) this.pending.delete(id);
    }
    const id = randomBytes(32).toString("base64url");
    this.pending.set(id, { login, expiresAt: now + this.validityMs });
    return id;
  }

  public peek(id: string | undefined): PendingHostedLogin | null {
    const entry = id ? this.pending.get(id) : undefined;
    if (!entry || entry.expiresAt <= this.clock.get().getTime()) return null;
    return entry.login;
  }

  public delete(id: string | undefined): void {
    if (id) this.pending.delete(id);
  }
}
