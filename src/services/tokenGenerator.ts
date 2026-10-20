import type { TimeUnitsType } from "@aws-sdk/client-cognito-identity-provider";
import type { StringMap } from "aws-lambda/trigger/cognito-user-pool-trigger/_common";
import type { GroupOverrideDetails } from "aws-lambda/trigger/cognito-user-pool-trigger/pre-token-generation";
import jwt, { type SignOptions } from "jsonwebtoken";
import * as uuid from "uuid";
import { InvalidParameterError } from "../errors";
import PrivateKey from "../keys/cognitoLocal.private.json";
import { identitiesClaim } from "../oauth2/federation";
import type { AppClient } from "./appClient";
import type { Clock } from "./clock";
import type { Context } from "./context";
import type { Triggers } from "./triggers";
import {
  attributesToRecord,
  attributeValue,
  customAttributes,
  type User,
} from "./userPoolService";

export interface TokenConfig {
  IssuerDomain?: string;
  /** Verify signature, expiry and revocation of tokens sent to the API; false decodes them unchecked. */
  Verify?: boolean;
  /** Require SECRET_HASH / ClientSecret from app clients that have a secret. */
  CheckSecretHash?: boolean;
}

export interface Token {
  client_id: string;
  iss: string;
  sub: string;
  token_use: string;
  username: string;
  event_id: string;
  scope: string;
  auth_time: Date;
  jti: string;
  origin_jti?: string;
  exp?: number;
}

interface TokenOverrides {
  claimsToAddOrOverride?: StringMap | undefined;
  claimsToSuppress?: string[] | undefined;
  groupOverrideDetails?: GroupOverrideDetails | undefined;
}

const RESERVED_CLAIMS = [
  "acr",
  "amr",
  "aud",
  "at_hash",
  "auth_time",
  "azp",
  "cognito:username",
  "exp",
  "iat",
  "identities",
  "iss",
  "jti",
  "nbf",
  "nonce",
  "origin_jti",
  "sub",
  "token_use",
];

type RawToken = Record<
  string,
  string | number | boolean | undefined | readonly string[] | object
>;

const STANDARD_ID_TOKEN_CLAIMS = [
  "name",
  "given_name",
  "family_name",
  "middle_name",
  "nickname",
  "preferred_username",
  "profile",
  "picture",
  "website",
  "gender",
  "birthdate",
  "zoneinfo",
  "locale",
  "updated_at",
  "phone_number",
];

function standardClaims(user: User): RawToken {
  const claims: RawToken = {};
  for (const name of STANDARD_ID_TOKEN_CLAIMS) {
    const value = attributeValue(name, user.Attributes);
    if (value !== undefined) claims[name] = value;
  }
  const phoneVerified = attributeValue(
    "phone_number_verified",
    user.Attributes,
  );
  if (phoneVerified !== undefined) {
    claims.phone_number_verified = phoneVerified === "true";
  }
  const address = attributeValue("address", user.Attributes);
  if (address !== undefined) claims.address = { formatted: address };
  const identities = identitiesClaim(user.Attributes);
  if (identities) claims.identities = identities;
  return claims;
}

const applyTokenOverrides = (
  token: RawToken,
  overrides: TokenOverrides,
): RawToken => {
  // TODO: support group overrides

  const claimsToSuppress = (overrides?.claimsToSuppress ?? []).filter(
    (claim) => !RESERVED_CLAIMS.includes(claim),
  );

  const claimsToOverride = Object.entries(
    overrides?.claimsToAddOrOverride ?? [],
  ).filter(([claim]) => !RESERVED_CLAIMS.includes(claim));

  return Object.fromEntries(
    [...Object.entries(token), ...claimsToOverride].filter(
      ([claim]) => !claimsToSuppress.includes(claim),
    ),
  );
};

export interface Tokens {
  readonly AccessToken: string;
  readonly IdToken: string;
  readonly RefreshToken: string;
  /** Lifetime of the access token in seconds. */
  readonly ExpiresIn: number;
  readonly TokenType: "Bearer";
}

export interface GenerateOptions {
  /** Reuse the session of an existing refresh token instead of starting a new one. */
  originJti?: string;
}

export interface TokenGenerator {
  generate(
    ctx: Context,
    user: User,
    userGroups: readonly string[],
    userPoolClient: AppClient,
    clientMetadata: Record<string, string> | undefined,
    source:
      | "AuthenticateDevice"
      | "Authentication"
      | "HostedAuth"
      | "NewPasswordChallenge"
      | "RefreshTokens",
    scopes?: readonly string[],
    options?: GenerateOptions,
  ): Promise<Tokens>;
}

const UNIT_SECONDS: Record<TimeUnitsType, number> = {
  seconds: 1,
  minutes: 60,
  hours: 60 * 60,
  days: 24 * 60 * 60,
};

export const DEFAULT_TOKEN_VALIDITY = {
  AccessToken: { value: 1, unit: "hours" },
  IdToken: { value: 1, unit: "hours" },
  RefreshToken: { value: 30, unit: "days" },
} as const satisfies Record<
  "AccessToken" | "IdToken" | "RefreshToken",
  { value: number; unit: TimeUnitsType }
>;

const VALIDITY_FIELD = {
  AccessToken: "AccessTokenValidity",
  IdToken: "IdTokenValidity",
  RefreshToken: "RefreshTokenValidity",
} as const;

export const tokenValiditySeconds = (
  client: Pick<
    AppClient,
    | "AccessTokenValidity"
    | "IdTokenValidity"
    | "RefreshTokenValidity"
    | "TokenValidityUnits"
  >,
  token: keyof typeof VALIDITY_FIELD,
): number => {
  const configured = client[VALIDITY_FIELD[token]];
  if (configured === undefined || configured === null) {
    const fallback = DEFAULT_TOKEN_VALIDITY[token];
    return fallback.value * UNIT_SECONDS[fallback.unit];
  }
  const unit =
    client.TokenValidityUnits?.[token] ?? DEFAULT_TOKEN_VALIDITY[token].unit;
  const multiplier = UNIT_SECONDS[unit];
  if (!multiplier) {
    throw new Error(`Invalid unit: ${unit}`);
  }
  return configured * multiplier;
};

const VALIDITY_LIMITS_SECONDS = {
  AccessToken: [5 * 60, 24 * 60 * 60],
  IdToken: [5 * 60, 24 * 60 * 60],
  RefreshToken: [60 * 60, 3650 * 24 * 60 * 60],
} as const;

/** AWS limits: access and ID tokens 5 minutes to 1 day, refresh tokens 60 minutes to 10 years. */
export const assertTokenValidity = (
  client: Parameters<typeof tokenValiditySeconds>[0],
): void => {
  for (const token of Object.keys(
    VALIDITY_FIELD,
  ) as (keyof typeof VALIDITY_FIELD)[]) {
    if (client[VALIDITY_FIELD[token]] === undefined) continue;
    const seconds = tokenValiditySeconds(client, token);
    const [min, max] = VALIDITY_LIMITS_SECONDS[token];
    if (!(seconds >= min && seconds <= max)) {
      throw new InvalidParameterError("Invalid range for token validity.");
    }
  }
};

export class JwtTokenGenerator implements TokenGenerator {
  private readonly clock: Clock;
  private readonly triggers: Triggers;
  private readonly tokenConfig: TokenConfig;

  public constructor(
    clock: Clock,
    triggers: Triggers,
    tokenConfig: TokenConfig,
  ) {
    this.clock = clock;
    this.triggers = triggers;
    this.tokenConfig = tokenConfig;
  }

  public async generate(
    ctx: Context,
    user: User,
    userGroups: readonly string[],
    userPoolClient: AppClient,
    clientMetadata: Record<string, string> | undefined,
    source:
      | "AuthenticateDevice"
      | "Authentication"
      | "HostedAuth"
      | "NewPasswordChallenge"
      | "RefreshTokens",
    scopes?: readonly string[],
    options: GenerateOptions = {},
  ): Promise<Tokens> {
    const eventId = uuid.v4();
    const originJti = options.originJti ?? uuid.v4();
    const authTime = Math.floor(this.clock.get().getTime() / 1000);
    const sub = attributeValue("sub", user.Attributes);

    const accessToken: RawToken = {
      auth_time: authTime,
      client_id: userPoolClient.ClientId,
      event_id: eventId,
      iat: authTime,
      jti: uuid.v4(),
      origin_jti: originJti,
      scope: scopes?.length
        ? scopes.join(" ")
        : "aws.cognito.signin.user.admin",
      sub,
      token_use: "access",
      username: user.Username,
    };
    let idToken: RawToken = {
      ...standardClaims(user),
      "cognito:username": user.Username,
      auth_time: authTime,
      email: attributeValue("email", user.Attributes),
      email_verified:
        attributeValue("email_verified", user.Attributes) === "true",
      event_id: eventId,
      iat: authTime,
      jti: uuid.v4(),
      origin_jti: originJti,
      sub,
      token_use: "id",
      ...attributesToRecord(customAttributes(user.Attributes)),
    };

    if (userGroups.length) {
      accessToken["cognito:groups"] = userGroups;
      idToken["cognito:groups"] = userGroups;
    }

    if (
      this.triggers.enabled("PreTokenGeneration", userPoolClient.UserPoolId)
    ) {
      const result = await this.triggers.preTokenGeneration(ctx, {
        clientId: userPoolClient.ClientId,
        clientMetadata,
        source,
        userAttributes: user.Attributes,
        username: user.Username,
        groupConfiguration: {
          // TODO: this should be populated from the user's groups
          groupsToOverride: undefined,
          iamRolesToOverride: undefined,
          preferredRole: undefined,
        },
        userPoolId: userPoolClient.UserPoolId,
      });

      idToken = applyTokenOverrides(idToken, result.claimsOverrideDetails);
    }

    const issuer = `${this.tokenConfig.IssuerDomain}/${userPoolClient.UserPoolId}`;

    const accessTokenSeconds = tokenValiditySeconds(
      userPoolClient,
      "AccessToken",
    );

    return {
      AccessToken: jwt.sign(accessToken, PrivateKey.pem, {
        algorithm: "RS256",
        issuer,
        expiresIn: accessTokenSeconds,
        keyid: "CognitoLocal",
      } satisfies SignOptions),
      IdToken: jwt.sign(idToken, PrivateKey.pem, {
        algorithm: "RS256",
        issuer,
        expiresIn: tokenValiditySeconds(userPoolClient, "IdToken"),
        audience: userPoolClient.ClientId,
        keyid: "CognitoLocal",
      } satisfies SignOptions),
      // A readable stand-in: AWS refresh tokens are encrypted. jti is the session id (origin_jti).
      RefreshToken: jwt.sign(
        {
          "cognito:username": user.Username,
          client_id: userPoolClient.ClientId,
          email: attributeValue("email", user.Attributes),
          iat: authTime,
          jti: originJti,
          ...(scopes?.length ? { scope: scopes.join(" ") } : {}),
        },
        PrivateKey.pem,
        {
          algorithm: "RS256",
          issuer,
          expiresIn: tokenValiditySeconds(userPoolClient, "RefreshToken"),
          keyid: "CognitoLocal",
        } satisfies SignOptions,
      ),
      ExpiresIn: accessTokenSeconds,
      TokenType: "Bearer",
    };
  }
}
