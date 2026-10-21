import type { TimeUnitsType } from "@aws-sdk/client-cognito-identity-provider";
import jwt, { type SignOptions } from "jsonwebtoken";
import * as uuid from "uuid";
import { InvalidParameterError } from "../errors";
import PrivateKey from "../keys/cognitoLocal.private.json";
import { identitiesClaim } from "../oauth2/federation";
import type { AppClient } from "./appClient";
import type { Clock } from "./clock";
import type { CognitoService } from "./cognitoService";
import type { Context } from "./context";
import {
  applyGroupClaims,
  applyPreTokenGenerationResponse,
  type Claims,
  groupConfigurationFor,
} from "./tokenCustomization";
import type { Triggers } from "./triggers";
import {
  attributesToRecord,
  attributeValue,
  customAttributes,
  type Group,
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

/** The groups of a user pool, for the role claims of ID tokens. */
export type GroupLookup = (
  ctx: Context,
  userPoolId: string,
) => Promise<readonly Group[]>;

export const poolGroups =
  (cognito: Pick<CognitoService, "getUserPool">): GroupLookup =>
  async (ctx, userPoolId) =>
    (await cognito.getUserPool(ctx, userPoolId)).listGroups(ctx);

export class JwtTokenGenerator implements TokenGenerator {
  private readonly clock: Clock;
  private readonly triggers: Triggers;
  private readonly tokenConfig: TokenConfig;
  private readonly groupLookup: GroupLookup | undefined;

  public constructor(
    clock: Clock,
    triggers: Triggers,
    tokenConfig: TokenConfig,
    groupLookup?: GroupLookup,
  ) {
    this.clock = clock;
    this.triggers = triggers;
    this.tokenConfig = tokenConfig;
    this.groupLookup = groupLookup;
  }

  private async groupsOf(
    ctx: Context,
    userPoolId: string,
    userGroups: readonly string[],
  ): Promise<Pick<Group, "GroupName" | "RoleArn" | "Precedence">[]> {
    const poolGroups = this.groupLookup
      ? await this.groupLookup(ctx, userPoolId)
      : [];
    return userGroups.map(
      (name) =>
        poolGroups.find((g) => g.GroupName === name) ?? { GroupName: name },
    );
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
    const idToken: RawToken = {
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

    const groupConfiguration = groupConfigurationFor(
      await this.groupsOf(ctx, userPoolClient.UserPoolId, userGroups),
    );
    applyGroupClaims(idToken, accessToken, groupConfiguration);

    let claims: { idToken: Claims; accessToken: Claims } = {
      idToken,
      accessToken,
    };
    if (
      this.triggers.enabled("PreTokenGeneration", userPoolClient.UserPoolId)
    ) {
      const version =
        this.triggers.preTokenGenerationVersion(userPoolClient.UserPoolId) ??
        "1";
      const response = await this.triggers.preTokenGeneration(ctx, {
        clientId: userPoolClient.ClientId,
        clientMetadata,
        source,
        version,
        userAttributes: user.Attributes,
        username: user.Username,
        groupConfiguration,
        scopes: String(accessToken.scope).split(" "),
        userPoolId: userPoolClient.UserPoolId,
      });
      const customized = applyPreTokenGenerationResponse(
        version,
        response,
        claims,
        userPoolClient.ClientId,
      );
      claims = {
        idToken: customized.idToken ?? idToken,
        accessToken: customized.accessToken,
      };
    }

    const issuer = `${this.tokenConfig.IssuerDomain}/${userPoolClient.UserPoolId}`;

    const accessTokenSeconds = tokenValiditySeconds(
      userPoolClient,
      "AccessToken",
    );

    return {
      AccessToken: jwt.sign(claims.accessToken, PrivateKey.pem, {
        algorithm: "RS256",
        issuer,
        expiresIn: accessTokenSeconds,
        keyid: "CognitoLocal",
      } satisfies SignOptions),
      IdToken: jwt.sign(claims.idToken, PrivateKey.pem, {
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
