import type {
  ActiveAuthSession,
  AuthSession,
  AuthSessions,
} from "./authSessions";
import type { Clock } from "./clock";
import type { Context } from "./context";
import type { DeliveryDetails } from "./messageDelivery/messageDelivery";
import type { Messages } from "./messages";
import { attributeValue, type User } from "./userPoolService";

export const DEFAULT_CODE_LOG_SIZE = 100;

export type CodeType =
  | "SIGN_UP"
  | "FORGOT_PASSWORD"
  | "MFA"
  | "TEMPORARY_PASSWORD"
  | "ATTRIBUTE_VERIFICATION"
  | "CUSTOM_AUTH";

export interface CodeLogEntry {
  id: number;
  at: Date;
  type: CodeType;
  source: string;
  userPoolId: string;
  clientId?: string | null;
  username: string;
  email?: string;
  phoneNumber?: string;
  code?: string;
  deliveryMedium?: string;
  destination?: string;
  challengeName?: string;
  round?: number;
  privateChallengeParameters?: Record<string, string>;
  expiresAt?: Date;
}

export type NewCodeLogEntry = Omit<CodeLogEntry, "id" | "at">;

export interface CodeLog {
  record(entry: NewCodeLogEntry): CodeLogEntry;
  list(): readonly CodeLogEntry[];
}

export class InMemoryCodeLog implements CodeLog {
  private readonly entries: CodeLogEntry[] = [];
  private nextId = 1;

  public constructor(
    private readonly clock: Clock,
    private readonly capacity = DEFAULT_CODE_LOG_SIZE,
  ) {}

  public record(entry: NewCodeLogEntry): CodeLogEntry {
    const id = this.nextId;
    this.nextId = id + 1;
    const stored = { ...entry, id, at: this.clock.get() };
    this.entries.unshift(stored);
    if (this.entries.length > this.capacity) {
      this.entries.length = this.capacity;
    }
    return stored;
  }

  public list(): readonly CodeLogEntry[] {
    return [...this.entries];
  }
}

const SOURCE_TYPES: Record<string, CodeType> = {
  AdminCreateUser: "TEMPORARY_PASSWORD",
  Authentication: "MFA",
  ForgotPassword: "FORGOT_PASSWORD",
  ResendCode: "SIGN_UP",
  SignUp: "SIGN_UP",
  UpdateUserAttribute: "ATTRIBUTE_VERIFICATION",
  VerifyUserAttribute: "ATTRIBUTE_VERIFICATION",
};

const userContact = (user: User) => ({
  email: attributeValue("email", user.Attributes),
  phoneNumber: attributeValue("phone_number", user.Attributes),
});

// Records every code before it is handed to the real delivery path.
export class RecordingMessages implements Messages {
  public constructor(
    private readonly inner: Messages,
    private readonly codeLog: CodeLog,
  ) {}

  public deliver(
    ctx: Context,
    source: Parameters<Messages["deliver"]>[1],
    clientId: string | null,
    userPoolId: string,
    user: User,
    code: string,
    clientMetadata: Record<string, string> | undefined,
    deliveryDetails: DeliveryDetails,
  ): Promise<void> {
    this.codeLog.record({
      type: SOURCE_TYPES[source] ?? "SIGN_UP",
      source,
      userPoolId,
      clientId,
      username: user.Username,
      ...userContact(user),
      code,
      deliveryMedium: deliveryDetails?.DeliveryMedium,
      destination: deliveryDetails?.Destination,
    });
    return this.inner.deliver(
      ctx,
      source,
      clientId,
      userPoolId,
      user,
      code,
      clientMetadata,
      deliveryDetails,
    );
  }
}

export const customAuthRound = (session: AuthSession) =>
  session.history.filter((x) => x.challengeName === "CUSTOM_CHALLENGE").length +
  1;

export const challengeCode = (params: Record<string, string>) => {
  if (params.secretLoginCode) return params.secretLoginCode;
  const values = Object.values(params);
  return values.length === 1 ? values[0] : undefined;
};

// Records each CUSTOM_CHALLENGE round, so the OTP stays visible after the session is used.
export class RecordingAuthSessions implements AuthSessions {
  public constructor(
    private readonly inner: AuthSessions,
    private readonly codeLog: CodeLog,
  ) {}

  public create(session: AuthSession): string {
    const id = this.inner.create(session);
    const { pendingChallenge } = session;
    if (pendingChallenge.challengeName === "CUSTOM_CHALLENGE") {
      this.codeLog.record({
        type: "CUSTOM_AUTH",
        source: "CreateAuthChallenge",
        userPoolId: session.userPoolId,
        clientId: session.clientId,
        username: session.username,
        code: challengeCode(pendingChallenge.privateChallengeParameters),
        challengeName: pendingChallenge.challengeName,
        round: customAuthRound(session),
        privateChallengeParameters: pendingChallenge.privateChallengeParameters,
        expiresAt: this.inner.list().find((x) => x.id === id)?.expiresAt,
      });
    }
    return id;
  }

  public list(): ActiveAuthSession[] {
    return this.inner.list();
  }

  public peek(sessionId: string): AuthSession | undefined {
    return this.inner.peek(sessionId);
  }

  public take(sessionId: string): AuthSession {
    return this.inner.take(sessionId);
  }
}
