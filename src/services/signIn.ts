import type {
  ExplicitAuthFlowsType,
  InitiateAuthResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import {
  CodeMismatchError,
  InvalidParameterError,
  NotAuthorizedError,
  UnsupportedError,
} from "../errors";
import type { AppClient } from "./appClient";
import type { AuthSession, SignInState } from "./authSessions";
import type { Context } from "./context";
import {
  deviceTrackingEnabled,
  isRemembered,
  issueDevice,
  type NewDeviceMetadata,
  requireConfirmedDevice,
  updateDevice,
} from "./devices";
import type { Services } from "./index";
import type { DeliveryDetails } from "./messageDelivery/messageDelivery";
import {
  enabledMfaMethods,
  isMfaRequired,
  type MfaMethod,
  smsMfaDelivery,
} from "./mfa";
import { nextMfaStep } from "./mfaSetup";
import {
  newPasskeyChallenge,
  passkeySignInAvailable,
  verifyPasskeySignIn,
} from "./passkeys";
import { assertPasswordConformsToPolicy } from "./passwordPolicy";
import {
  startDeviceVerifier,
  startPasswordVerifier,
  verifyDeviceClaim,
  verifyPasswordClaim,
} from "./srp";
import { verify as verifyTotp } from "./totp";
import {
  attribute,
  attributesAppend,
  attributesToRecord,
  attributeValue,
  type User,
  type UserPoolService,
} from "./userPoolService";

export type SignInServices = Pick<
  Services,
  | "authSessions"
  | "clock"
  | "messages"
  | "otp"
  | "srpSessions"
  | "tokenGenerator"
  | "triggers"
> &
  Partial<Pick<Services, "config">>;

export type SignInResponse = Pick<
  InitiateAuthResponse,
  | "AuthenticationResult"
  | "AvailableChallenges"
  | "ChallengeName"
  | "ChallengeParameters"
  | "Session"
>;

type TokenSource = "Authentication" | "NewPasswordChallenge";

export interface SignInRound {
  userPool: UserPoolService;
  client: AppClient;
  user: User;
  deviceKey?: string;
  /** ClientMetadata for CustomMessage when a code is sent. */
  clientMetadata?: Record<string, string>;
  postAuthenticationClientMetadata?: Record<string, string>;
  tokenClientMetadata?: Record<string, string>;
  tokenSource?: TokenSource;
}

export type FirstFactor =
  | "PASSWORD"
  | "PASSWORD_SRP"
  | "EMAIL_OTP"
  | "SMS_OTP"
  | "WEB_AUTHN";

const FIRST_FACTORS: readonly string[] = [
  "PASSWORD",
  "PASSWORD_SRP",
  "EMAIL_OTP",
  "SMS_OTP",
  "WEB_AUTHN",
];

// CreateUserPoolClient: a client without ExplicitAuthFlows supports these.
const DEFAULT_EXPLICIT_AUTH_FLOWS: readonly ExplicitAuthFlowsType[] = [
  "ALLOW_REFRESH_TOKEN_AUTH",
  "ALLOW_USER_SRP_AUTH",
  "ALLOW_CUSTOM_AUTH",
];

export const assertUserAuthAllowed = (client: AppClient): void => {
  const flows = client.ExplicitAuthFlows ?? DEFAULT_EXPLICIT_AUTH_FLOWS;
  if (!flows.includes("ALLOW_USER_AUTH")) {
    throw new InvalidParameterError(
      "USER_AUTH flow not enabled for this client",
    );
  }
};

/** The first factors a user can choose in USER_AUTH, in the order AvailableChallenges lists them. */
export const availableFirstFactors = (
  userPool: UserPoolService,
  user: User,
): FirstFactor[] => {
  const allowed =
    userPool.options.Policies?.SignInPolicy?.AllowedFirstAuthFactors ?? [];
  // One-time passwords are not offered to users who must pass MFA.
  const passwordless = !isMfaRequired(userPool.options, user);
  const factors: FirstFactor[] = [];
  if (passkeySignInAvailable(userPool.options, user)) {
    factors.push("WEB_AUTHN");
  }
  if (
    passwordless &&
    allowed.includes("EMAIL_OTP") &&
    attributeValue("email", user.Attributes)
  ) {
    factors.push("EMAIL_OTP");
  }
  if (
    passwordless &&
    allowed.includes("SMS_OTP") &&
    attributeValue("phone_number", user.Attributes)
  ) {
    factors.push("SMS_OTP");
  }
  if (user.Password) {
    factors.push("PASSWORD", "PASSWORD_SRP");
  }
  return factors;
};

const createSession = (
  services: SignInServices,
  round: SignInRound,
  challengeName: string,
  state: SignInState = {},
): string =>
  services.authSessions.create(
    {
      userPoolId: round.userPool.options.Id,
      clientId: round.client.ClientId,
      username: round.user.Username,
      clientMetadata: round.clientMetadata,
      history: [],
      pendingChallenge: { challengeName, privateChallengeParameters: {} },
      signIn: {
        ...(round.deviceKey ? { deviceKey: round.deviceKey } : {}),
        ...(round.tokenSource ? { tokenSource: round.tokenSource } : {}),
        ...state,
      },
    },
    round.client.AuthSessionValidity,
  );

const otpDelivery = (
  factor: "EMAIL_OTP" | "SMS_OTP",
  user: User,
): DeliveryDetails | null => {
  if (factor === "EMAIL_OTP") {
    const email = attributeValue("email", user.Attributes);
    return email
      ? { DeliveryMedium: "EMAIL", AttributeName: "email", Destination: email }
      : null;
  }
  return smsMfaDelivery(user);
};

const sendCode = async (
  ctx: Context,
  services: SignInServices,
  round: SignInRound,
  delivery: DeliveryDetails,
): Promise<string> => {
  const code = services.otp();
  await services.messages.deliver(
    ctx,
    "Authentication",
    round.client.ClientId,
    round.userPool.options.Id,
    round.user,
    code,
    round.clientMetadata,
    delivery,
  );
  return code;
};

const newPasswordChallenge = (
  services: SignInServices,
  round: SignInRound,
): SignInResponse => ({
  ChallengeName: "NEW_PASSWORD_REQUIRED",
  ChallengeParameters: {
    USER_ID_FOR_SRP: round.user.Username,
    requiredAttributes: JSON.stringify([]),
    userAttributes: JSON.stringify(attributesToRecord(round.user.Attributes)),
  },
  Session: createSession(services, round, "NEW_PASSWORD_REQUIRED", {
    tokenSource: "NewPasswordChallenge",
  }),
});

export const finishSignIn = async (
  ctx: Context,
  services: SignInServices,
  round: SignInRound,
  source: TokenSource | "AuthenticateDevice" = round.tokenSource ??
    "Authentication",
): Promise<SignInResponse> => {
  const { userPool, user, client } = round;
  if (services.triggers.enabled("PostAuthentication", userPool.options.Id)) {
    await services.triggers.postAuthentication(ctx, {
      clientId: client.ClientId,
      clientMetadata: round.postAuthenticationClientMetadata,
      source: "PostAuthentication_Authentication",
      userAttributes: user.Attributes,
      username: user.Username,
      userPoolId: userPool.options.Id,
    });
  }

  const userGroups = await userPool.listUserGroupMembership(ctx, user);
  const tokens = await services.tokenGenerator.generate(
    ctx,
    user,
    userGroups,
    client,
    round.tokenClientMetadata,
    source,
  );
  await userPool.storeRefreshToken(ctx, tokens.RefreshToken, user);

  let newDevice: NewDeviceMetadata | undefined;
  if (deviceTrackingEnabled(userPool.options) && !round.deviceKey) {
    await userPool.updateUser(ctx, user, (latest) => {
      const issued = issueDevice(
        userPool.options.Id,
        latest,
        services.clock.get(),
      );
      newDevice = issued.metadata;
      return issued.user;
    });
  }

  return {
    ChallengeParameters: {},
    AuthenticationResult: {
      ...tokens,
      ...(newDevice ? { NewDeviceMetadata: newDevice } : {}),
    },
  };
};

const smsMfaChallenge = async (
  ctx: Context,
  services: SignInServices,
  round: SignInRound,
): Promise<SignInResponse> => {
  const delivery = smsMfaDelivery(round.user);
  if (!delivery) {
    throw new InvalidParameterError(
      "SMS_MFA requires a phone_number attribute for the user",
    );
  }
  const code = await sendCode(ctx, services, round, delivery);
  await round.userPool.updateUser(ctx, round.user, (latest) => ({
    ...latest,
    MFACode: code,
  }));
  return {
    ChallengeName: "SMS_MFA",
    ChallengeParameters: {
      CODE_DELIVERY_DELIVERY_MEDIUM: "SMS",
      CODE_DELIVERY_DESTINATION: delivery.Destination,
      USER_ID_FOR_SRP: round.user.Username,
    },
    Session: createSession(services, round, "SMS_MFA", { code }),
  };
};

export const mfaChallenge = async (
  ctx: Context,
  services: SignInServices,
  round: SignInRound,
  method: MfaMethod,
): Promise<SignInResponse> => {
  if (method === "SMS_MFA") {
    return smsMfaChallenge(ctx, services, round);
  }
  const friendlyName =
    round.user.SoftwareTokenMfaConfiguration?.FriendlyDeviceName;
  return {
    ChallengeName: "SOFTWARE_TOKEN_MFA",
    ChallengeParameters: {
      USER_ID_FOR_SRP: round.user.Username,
      ...(friendlyName ? { FRIENDLY_DEVICE_NAME: friendlyName } : {}),
    },
    Session: createSession(services, round, "SOFTWARE_TOKEN_MFA"),
  };
};

/** MFA, device authentication or tokens, once the user has proven their first factor. */
export const afterFirstFactor = async (
  ctx: Context,
  services: SignInServices,
  round: SignInRound,
  mfaSatisfied = false,
): Promise<SignInResponse> => {
  const { userPool, user } = round;
  const tracking = deviceTrackingEnabled(userPool.options);
  const device =
    tracking && round.deviceKey
      ? requireConfirmedDevice(user, round.deviceKey)
      : undefined;
  const step = mfaSatisfied
    ? ({ kind: "none" } as const)
    : nextMfaStep(userPool.options, user);

  const deviceCanAuthenticate =
    device && isRemembered(device) && device.DeviceSecretVerifierConfig;
  if (
    deviceCanAuthenticate &&
    (step.kind === "none" ||
      userPool.options.DeviceConfiguration?.ChallengeRequiredOnNewDevice)
  ) {
    return {
      ChallengeName: "DEVICE_SRP_AUTH",
      ChallengeParameters: {},
      Session: createSession(services, round, "DEVICE_SRP_AUTH"),
    };
  }

  switch (step.kind) {
    case "none":
      return finishSignIn(ctx, services, round);
    case "unavailable":
      throw new NotAuthorizedError();
    case "challenge":
      return mfaChallenge(ctx, services, round, step.method);
    case "select":
      return {
        ChallengeName: "SELECT_MFA_TYPE",
        ChallengeParameters: {
          USER_ID_FOR_SRP: user.Username,
          MFAS_CAN_CHOOSE: JSON.stringify(step.methods),
        },
        Session: createSession(services, round, "SELECT_MFA_TYPE"),
      };
    case "setup":
      return {
        ChallengeName: "MFA_SETUP",
        ChallengeParameters: {
          MFAS_CAN_SETUP: JSON.stringify(step.options),
          USER_ID_FOR_SRP: user.Username,
        },
        Session: createSession(services, round, "MFA_SETUP"),
      };
  }
};

/** A temporary password must be replaced before anything else; otherwise continue to MFA or tokens. */
export const afterPassword = (
  ctx: Context,
  services: SignInServices,
  round: SignInRound,
): Promise<SignInResponse> =>
  round.user.UserStatus === "FORCE_CHANGE_PASSWORD"
    ? Promise.resolve(newPasswordChallenge(services, round))
    : afterFirstFactor(ctx, services, round);

export const passwordVerifierChallenge = (
  services: SignInServices,
  round: SignInRound,
  srpA: string | undefined,
): SignInResponse => {
  const parameters = startPasswordVerifier(services.srpSessions, {
    userPoolId: round.userPool.options.Id,
    clientId: round.client.ClientId,
    user: round.user,
    srpA,
    validityMinutes: round.client.AuthSessionValidity,
    deviceKey: round.deviceKey,
  });
  return {
    ChallengeName: "PASSWORD_VERIFIER",
    ChallengeParameters: parameters,
    Session: createSession(services, round, "PASSWORD_VERIFIER"),
  };
};

const startFirstFactor = async (
  ctx: Context,
  services: SignInServices,
  round: SignInRound,
  factor: FirstFactor,
  parameters: Record<string, string>,
): Promise<SignInResponse> => {
  if (factor === "PASSWORD") {
    if (!parameters.PASSWORD) {
      throw new InvalidParameterError("Missing required parameter PASSWORD");
    }
    if (parameters.PASSWORD !== round.user.Password) {
      throw new NotAuthorizedError("Incorrect username or password.");
    }
    return afterPassword(ctx, services, round);
  }
  if (factor === "PASSWORD_SRP") {
    if (!parameters.SRP_A) {
      throw new InvalidParameterError("Missing required parameter SRP_A");
    }
    return passwordVerifierChallenge(services, round, parameters.SRP_A);
  }
  if (factor === "WEB_AUTHN") {
    const passkey = newPasskeyChallenge(round.userPool.options, round.user);
    return {
      ChallengeName: "WEB_AUTHN",
      ChallengeParameters: {
        CREDENTIAL_REQUEST_OPTIONS: JSON.stringify(passkey.options),
      },
      Session: createSession(services, round, "WEB_AUTHN", {
        webAuthnChallenge: passkey.challenge,
        webAuthnRequireUserVerification: passkey.requireUserVerification,
      }),
    };
  }

  const delivery = otpDelivery(factor, round.user);
  if (!delivery) {
    throw new InvalidParameterError(`${factor} is not available for the user`);
  }
  const code = await sendCode(ctx, services, round, delivery);
  return {
    ChallengeName: factor,
    ChallengeParameters: {
      CODE_DELIVERY_DELIVERY_MEDIUM: delivery.DeliveryMedium,
      CODE_DELIVERY_DESTINATION: delivery.Destination,
    },
    Session: createSession(services, round, factor, { code }),
  };
};

/** InitiateAuth / AdminInitiateAuth with AuthFlow USER_AUTH (choice-based sign-in). */
export const startUserAuth = async (
  ctx: Context,
  services: SignInServices,
  round: SignInRound,
  authParameters: Record<string, string>,
): Promise<SignInResponse> => {
  const available = availableFirstFactors(round.userPool, round.user);
  if (available.length === 0) {
    throw new NotAuthorizedError("Incorrect username or password.");
  }
  const preferred = authParameters.PREFERRED_CHALLENGE as FirstFactor;
  if (preferred && available.includes(preferred)) {
    return startFirstFactor(ctx, services, round, preferred, authParameters);
  }
  return {
    ChallengeName: "SELECT_CHALLENGE",
    ChallengeParameters: {},
    AvailableChallenges: available,
    Session: createSession(services, round, "SELECT_CHALLENGE", {
      availableChallenges: available,
    }),
  };
};

export interface ChallengeAnswer {
  userPool: UserPoolService;
  client: AppClient;
  user: User;
  sessionId: string | undefined;
  challengeName: string | undefined;
  challengeResponses: Record<string, string>;
  clientMetadata?: Record<string, string>;
  operation: string;
}

const SESSION_CHALLENGES = new Set([
  "SELECT_CHALLENGE",
  "PASSWORD",
  "PASSWORD_SRP",
  "EMAIL_OTP",
  "SMS_OTP",
  "WEB_AUTHN",
  "MFA_SETUP",
  "DEVICE_SRP_AUTH",
  "DEVICE_PASSWORD_VERIFIER",
]);

const findSignInSession = (
  services: SignInServices,
  answer: ChallengeAnswer,
): AuthSession | undefined => {
  const session = answer.sessionId
    ? services.authSessions.peek(answer.sessionId)
    : undefined;
  if (!session?.signIn) {
    if (answer.challengeName && SESSION_CHALLENGES.has(answer.challengeName)) {
      // take() reports a missing or expired session with Cognito's message.
      services.authSessions.take(answer.sessionId ?? "");
      throw new NotAuthorizedError("Invalid session for the user.");
    }
    return undefined;
  }
  if (
    session.clientId !== answer.client.ClientId ||
    session.userPoolId !== answer.userPool.options.Id ||
    session.username !== answer.user.Username
  ) {
    throw new NotAuthorizedError("Invalid session for the user.");
  }

  const pending = session.pendingChallenge.challengeName;
  const choosesFactor =
    pending === "SELECT_CHALLENGE" &&
    (answer.challengeName === "PASSWORD" ||
      answer.challengeName === "PASSWORD_SRP") &&
    session.signIn.availableChallenges?.includes(answer.challengeName);
  if (pending !== answer.challengeName && !choosesFactor) {
    throw new InvalidParameterError(`Expected ChallengeName ${pending}`);
  }
  return session;
};

const markDeliveryVerified = (
  ctx: Context,
  services: SignInServices,
  round: SignInRound,
  attributeName: "email" | "phone_number",
): Promise<User> =>
  round.userPool.updateUser(ctx, round.user, (latest) => ({
    ...latest,
    Attributes: attributesAppend(
      latest.Attributes,
      attribute(`${attributeName}_verified`, "true"),
    ),
    UserStatus:
      latest.UserStatus === "UNCONFIRMED" ? "CONFIRMED" : latest.UserStatus,
    UserLastModifiedDate: services.clock.get(),
  }));

/** RespondToAuthChallenge / AdminRespondToAuthChallenge for every built-in challenge. */
export const respondToSignInChallenge = async (
  ctx: Context,
  services: SignInServices,
  answer: ChallengeAnswer,
): Promise<SignInResponse> => {
  const session = findSignInSession(services, answer);
  const state = session?.signIn ?? {};
  const responses = answer.challengeResponses;
  const consume = () => {
    if (session && answer.sessionId)
      services.authSessions.take(answer.sessionId);
  };
  const round: SignInRound = {
    userPool: answer.userPool,
    client: answer.client,
    user: answer.user,
    deviceKey: responses.DEVICE_KEY || state.deviceKey,
    clientMetadata: answer.clientMetadata ?? session?.clientMetadata,
    postAuthenticationClientMetadata: answer.clientMetadata,
    tokenClientMetadata: answer.clientMetadata,
    tokenSource: state.tokenSource,
  };
  const { userPool, user } = round;

  switch (answer.challengeName) {
    case "SELECT_CHALLENGE":
    case "PASSWORD":
    case "PASSWORD_SRP": {
      const factor =
        answer.challengeName === "SELECT_CHALLENGE"
          ? responses.ANSWER
          : answer.challengeName;
      if (
        !FIRST_FACTORS.includes(factor) ||
        !state.availableChallenges?.includes(factor)
      ) {
        throw new InvalidParameterError(
          `ANSWER must be one of ${JSON.stringify(state.availableChallenges ?? [])}`,
        );
      }
      const response = await startFirstFactor(
        ctx,
        services,
        round,
        factor as FirstFactor,
        responses,
      );
      consume();
      return response;
    }

    case "EMAIL_OTP":
    case "SMS_OTP": {
      const code = responses[`${answer.challengeName}_CODE`];
      if (!code || code !== state.code) {
        throw new CodeMismatchError();
      }
      consume();
      round.user = await markDeliveryVerified(
        ctx,
        services,
        round,
        answer.challengeName === "EMAIL_OTP" ? "email" : "phone_number",
      );
      return afterFirstFactor(ctx, services, round);
    }

    case "WEB_AUTHN": {
      const passkey = await verifyPasskeySignIn(ctx, {
        userPool,
        user,
        credential: responses.CREDENTIAL,
        challenge: state.webAuthnChallenge,
        requireUserVerification: !!state.webAuthnRequireUserVerification,
        clock: services.clock,
      });
      consume();
      round.user = passkey.user;
      return afterFirstFactor(ctx, services, round, passkey.satisfiesMfa);
    }

    case "PASSWORD_VERIFIER": {
      const verified = verifyPasswordClaim(services.srpSessions, {
        userPoolId: userPool.options.Id,
        clientId: answer.client.ClientId,
        user,
        challengeResponses: responses,
      });
      consume();
      round.deviceKey = round.deviceKey || verified.deviceKey;
      return afterPassword(ctx, services, round);
    }

    case "NEW_PASSWORD_REQUIRED": {
      if (!responses.NEW_PASSWORD) {
        throw new InvalidParameterError(
          "Missing required parameter NEW_PASSWORD",
        );
      }
      assertPasswordConformsToPolicy(
        services.config,
        userPool.options,
        responses.NEW_PASSWORD,
      );
      consume();
      round.user = await userPool.updateUser(ctx, user, (latest) => ({
        ...latest,
        Password: responses.NEW_PASSWORD,
        UserLastModifiedDate: services.clock.get(),
        UserStatus: "CONFIRMED",
      }));
      round.tokenSource = "NewPasswordChallenge";
      return afterFirstFactor(ctx, services, round);
    }

    case "SELECT_MFA_TYPE": {
      const method = enabledMfaMethods(user).find(
        (m) => m === responses.ANSWER,
      );
      if (!method) {
        throw new InvalidParameterError(
          "SELECT_MFA_TYPE requires ANSWER of SMS_MFA or SOFTWARE_TOKEN_MFA",
        );
      }
      consume();
      return mfaChallenge(ctx, services, round, method);
    }

    case "SMS_MFA": {
      const expected = state.code ?? user.MFACode;
      if (!expected || responses.SMS_MFA_CODE !== expected) {
        throw new CodeMismatchError();
      }
      consume();
      round.user = await userPool.updateUser(ctx, user, (latest) => ({
        ...latest,
        MFACode: undefined,
        UserLastModifiedDate: services.clock.get(),
      }));
      return finishSignIn(ctx, services, round);
    }

    case "SOFTWARE_TOKEN_MFA": {
      const code = responses.SOFTWARE_TOKEN_MFA_CODE;
      const totp = user.SoftwareTokenMfaConfiguration;
      if (
        !code ||
        !totp?.Secret ||
        !totp.Verified ||
        !verifyTotp(totp.Secret, code)
      ) {
        throw new CodeMismatchError();
      }
      consume();
      return finishSignIn(ctx, services, round);
    }

    case "MFA_SETUP": {
      if (!state.totpVerified) {
        throw new NotAuthorizedError("Invalid session for the user.");
      }
      consume();
      return finishSignIn(ctx, services, round);
    }

    case "DEVICE_SRP_AUTH": {
      const device = requireConfirmedDevice(user, round.deviceKey);
      if (!responses.SRP_A) {
        throw new InvalidParameterError("Missing required parameter SRP_A");
      }
      const verifier = device.DeviceSecretVerifierConfig;
      if (!verifier || !device.DeviceGroupKey || !isRemembered(device)) {
        throw new NotAuthorizedError("Incorrect username or password.");
      }
      const parameters = startDeviceVerifier(services.srpSessions, {
        userPoolId: userPool.options.Id,
        clientId: answer.client.ClientId,
        user,
        srpA: responses.SRP_A,
        validityMinutes: answer.client.AuthSessionValidity,
        deviceKey: device.DeviceKey,
        deviceGroupKey: device.DeviceGroupKey,
        passwordVerifier: verifier.PasswordVerifier,
        salt: verifier.Salt,
      });
      consume();
      round.deviceKey = device.DeviceKey;
      return {
        ChallengeName: "DEVICE_PASSWORD_VERIFIER",
        ChallengeParameters: parameters,
        Session: createSession(services, round, "DEVICE_PASSWORD_VERIFIER"),
      };
    }

    case "DEVICE_PASSWORD_VERIFIER": {
      const { deviceKey } = verifyDeviceClaim(services.srpSessions, {
        userPoolId: userPool.options.Id,
        clientId: answer.client.ClientId,
        user,
        challengeResponses: responses,
      });
      consume();
      const now = services.clock.get();
      round.deviceKey = deviceKey;
      round.user = await userPool.updateUser(ctx, user, (latest) =>
        updateDevice(latest, deviceKey, (device) => ({
          ...device,
          DeviceLastAuthenticatedDate: now,
        })),
      );
      return finishSignIn(ctx, services, round, "AuthenticateDevice");
    }

    default:
      throw new UnsupportedError(
        `${answer.operation} with ChallengeName=${answer.challengeName}`,
      );
  }
};

/** A sign-in session that waits for `challengeName`, for operations outside RespondToAuthChallenge. */
export const pendingSignInSession = (
  authSessions: Services["authSessions"],
  sessionId: string,
  challengeName: string,
): AuthSession => {
  const session = authSessions.peek(sessionId);
  if (!session?.signIn) {
    authSessions.take(sessionId);
    throw new NotAuthorizedError("Invalid session for the user.");
  }
  if (session.pendingChallenge.challengeName !== challengeName) {
    throw new NotAuthorizedError("Invalid session for the user.");
  }
  return session;
};

/** Replaces a sign-in session with a new one carrying `state`, as Cognito returns a new Session. */
export const advanceSignInSession = (
  authSessions: Services["authSessions"],
  sessionId: string,
  session: AuthSession,
  state: SignInState,
  validityMinutes: number | undefined,
): string => {
  authSessions.take(sessionId);
  return authSessions.create(
    { ...session, signIn: { ...session.signIn, ...state } },
    validityMinutes,
  );
};
