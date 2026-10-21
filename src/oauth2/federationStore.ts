import * as uuid from "uuid";
import type { ResponseType } from "./oauthRequest";
import type { RealSignIn } from "./realIdp";

const TTL_MS = 10 * 60 * 1000;

export interface PendingFederation {
  clientId: string;
  userPoolId: string;
  providerName: string;
  redirectUri: string;
  state: string | undefined;
  responseType: ResponseType;
  scopes: string[];
  codeChallenge: string | undefined;
  codeChallengeMethod: string | undefined;
  real?: RealSignIn;
}

interface Entry extends PendingFederation {
  expiresAt: number;
}

export class FederationStore {
  private readonly pending = new Map<string, Entry>();

  create(data: PendingFederation): string {
    const now = Date.now();
    for (const [id, entry] of this.pending) {
      if (entry.expiresAt < now) this.pending.delete(id);
    }
    const id = uuid.v4();
    this.pending.set(id, { ...data, expiresAt: now + TTL_MS });
    return id;
  }

  peek(id: string | undefined): PendingFederation | null {
    const entry = id ? this.pending.get(id) : undefined;
    if (!entry || Date.now() > entry.expiresAt) return null;
    const { expiresAt: _, ...data } = entry;
    return data;
  }

  consume(id: string | undefined): PendingFederation | null {
    const data = this.peek(id);
    if (id) this.pending.delete(id);
    return data;
  }
}
