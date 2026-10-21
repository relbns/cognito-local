import { randomBytes } from "node:crypto";
import { DEFAULT_AUTH_SESSION_VALIDITY_MINUTES } from "../services/authSessions";
import type { Clock } from "../services/clock";
import type { MfaMethod } from "../services/mfa";
import type { AuthorizeFlow } from "./oauthRequest";

/** Where a confirmation or reset code went, as SignUp and ForgotPassword report it. */
export interface CodeDelivery {
  DeliveryMedium?: string;
  Destination?: string;
}

export type HostedLoginStep =
  | { kind: "newPassword" }
  | { kind: "selectMfa"; methods: readonly MfaMethod[] }
  | { kind: "smsMfa"; code: string; destination: string }
  | { kind: "totpMfa" }
  | { kind: "mfaSetup"; secret: string; uri: string }
  | {
      kind: "passkey";
      challenge: string;
      requireUserVerification: boolean;
      options: object;
    }
  | {
      kind: "confirmSignUp";
      delivery: CodeDelivery | null;
      // True only when this browser just signed up with the password, so confirming can sign in.
      signInAfter: boolean;
    }
  | { kind: "confirmForgotPassword"; delivery: CodeDelivery | null };

export type HostedLoginStepKind = HostedLoginStep["kind"];

/** How long a confirm-code page stays valid: long enough to fetch the code from email or SMS. */
export const CODE_PAGE_VALIDITY_MS = 60 * 60_000;

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

  public create(
    login: PendingHostedLogin,
    validityMs = this.validityMs,
  ): string {
    const now = this.clock.get().getTime();
    for (const [id, entry] of this.pending) {
      if (entry.expiresAt <= now) this.pending.delete(id);
    }
    const id = randomBytes(32).toString("base64url");
    this.pending.set(id, { login, expiresAt: now + validityMs });
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
