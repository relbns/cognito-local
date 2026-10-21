import { createHmac, timingSafeEqual } from "node:crypto";
import jwt, { type JwtPayload } from "jsonwebtoken";
import {
  InvalidParameterError,
  NotAuthorizedError,
  TokenErrorMessages,
  UserNotFoundError,
} from "../errors";
import PublicKey from "../keys/cognitoLocal.public.json";
import type { AppClient } from "./appClient";
import type { Clock } from "./clock";
import type { CognitoService } from "./cognitoService";
import type { Context } from "./context";
import type { TokenConfig } from "./tokenGenerator";
import { epochSeconds, isTokenOriginActive } from "./tokenRevocation";
import {
  attributeValue,
  type User,
  type UserPoolService,
} from "./userPoolService";

export const ADMIN_SCOPE = "aws.cognito.signin.user.admin";

export interface AccessTokenClaims extends JwtPayload {
  client_id: string;
  username: string;
  sub: string;
  token_use: string;
  scope?: string;
  origin_jti?: string;
}

export interface RefreshTokenClaims extends JwtPayload {
  "cognito:username": string;
  client_id?: string;
  scope?: string;
}

export interface VerifiedAccessToken {
  claims: AccessTokenClaims;
  user: User;
  userPool: UserPoolService;
}

export interface VerifiedRefreshToken {
  claims: RefreshTokenClaims;
  user: User;
  userPool: UserPoolService;
}

export interface VerifyAccessTokenOptions {
  /** Cognito user APIs need aws.cognito.signin.user.admin; the userInfo endpoint does not. */
  requireAdminScope?: boolean;
}

export interface TokenVerifier {
  verifyAccessToken(
    ctx: Context,
    token: string | undefined,
    options?: VerifyAccessTokenOptions,
  ): Promise<VerifiedAccessToken>;
  verifyRefreshToken(
    ctx: Context,
    token: string | undefined,
    clientId: string,
  ): Promise<VerifiedRefreshToken>;
  verifySecretHash(
    client: AppClient,
    usernames: readonly (string | undefined)[],
    secretHash: string | undefined,
  ): void;
  verifyClientSecret(client: AppClient, clientSecret: string | undefined): void;
}

export const computeSecretHash = (
  username: string,
  clientId: string,
  clientSecret: string,
): string =>
  createHmac("sha256", clientSecret)
    .update(username + clientId)
    .digest("base64");

const safeEqual = (a: string, b: string): boolean => {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
};

const secretNotReceived = (client: AppClient) =>
  new NotAuthorizedError(
    `Client ${client.ClientId} is configured for secret but secret was not received`,
  );

const secretMismatch = (client: AppClient) =>
  new NotAuthorizedError(
    `Unable to verify secret hash for client ${client.ClientId}`,
  );

export const assertSecretHash = (
  client: AppClient,
  usernames: readonly (string | undefined)[],
  secretHash: string | undefined,
): void => {
  if (!client.ClientSecret) return;
  if (!secretHash) throw secretNotReceived(client);
  const secret = client.ClientSecret;
  const matches = usernames.some(
    (username) =>
      username !== undefined &&
      safeEqual(
        computeSecretHash(username, client.ClientId, secret),
        secretHash,
      ),
  );
  if (!matches) throw secretMismatch(client);
};

export const assertClientSecret = (
  client: AppClient,
  clientSecret: string | undefined,
): void => {
  if (!client.ClientSecret) return;
  if (!clientSecret) throw secretNotReceived(client);
  if (!safeEqual(client.ClientSecret, clientSecret)) {
    throw secretMismatch(client);
  }
};

/** The username part of SECRET_HASH for REFRESH_TOKEN_AUTH: sub when username is not a sign-in attribute. */
export const refreshSecretHashUsername = (
  userPool: UserPoolService,
  user: User,
): string | undefined =>
  userPool.options.UsernameAttributes?.length
    ? attributeValue("sub", user.Attributes)
    : user.Username;

const decodeObject = (token: string): JwtPayload | null => {
  const decoded = jwt.decode(token);
  return decoded && typeof decoded === "object" ? decoded : null;
};

const signatureValid = (token: string): boolean => {
  try {
    jwt.verify(token, PublicKey.pem, {
      algorithms: ["RS256"],
      ignoreExpiration: true,
      ignoreNotBefore: true,
    });
    return true;
  } catch {
    return false;
  }
};

const sameSubject = (user: User, sub: unknown): boolean => {
  const userSub = attributeValue("sub", user.Attributes);
  return !userSub || typeof sub !== "string" || userSub === sub;
};

export class JwtTokenVerifier implements TokenVerifier {
  private readonly clock: Clock;
  private readonly cognito: CognitoService;
  private readonly tokenConfig: TokenConfig;

  public constructor(
    clock: Clock,
    cognito: CognitoService,
    tokenConfig: TokenConfig,
  ) {
    this.clock = clock;
    this.cognito = cognito;
    this.tokenConfig = tokenConfig;
  }

  private get verifying(): boolean {
    return this.tokenConfig.Verify !== false;
  }

  private issuerFor(userPool: UserPoolService): string {
    return `${this.tokenConfig.IssuerDomain}/${userPool.options.Id}`;
  }

  public async verifyAccessToken(
    ctx: Context,
    token: string | undefined,
    { requireAdminScope = true }: VerifyAccessTokenOptions = {},
  ): Promise<VerifiedAccessToken> {
    if (!this.verifying) return this.decodeAccessTokenUnchecked(ctx, token);

    const invalid = () =>
      new NotAuthorizedError(TokenErrorMessages.invalidAccessToken);
    const claims = token ? decodeObject(token) : null;
    if (!token || !claims || !signatureValid(token)) throw invalid();
    if (claims.token_use !== "access" || typeof claims.client_id !== "string") {
      throw invalid();
    }

    const client = await this.cognito.getAppClient(ctx, claims.client_id);
    if (!client) throw invalid();
    const userPool = await this.cognito.getUserPoolForClientId(
      ctx,
      claims.client_id,
    );
    if (claims.iss !== this.issuerFor(userPool)) throw invalid();

    const now = this.clock.get();
    if (typeof claims.exp !== "number" || claims.exp <= epochSeconds(now)) {
      throw new NotAuthorizedError(TokenErrorMessages.expiredAccessToken);
    }

    if (claims.username === undefined && claims.sub === claims.client_id) {
      throw requireAdminScope
        ? new NotAuthorizedError(TokenErrorMessages.missingScope)
        : invalid();
    }

    const user = await userPool.getUserByUsername(
      ctx,
      String(claims.username ?? claims.sub ?? ""),
    );
    if (!user || !sameSubject(user, claims.sub)) {
      throw new UserNotFoundError(TokenErrorMessages.userDoesNotExist);
    }
    if (!user.Enabled) {
      throw new NotAuthorizedError(TokenErrorMessages.userDisabled);
    }
    if (!isTokenOriginActive(user, claims.origin_jti, now)) {
      throw new NotAuthorizedError(TokenErrorMessages.revokedAccessToken);
    }

    const scopes = String(claims.scope ?? "").split(" ");
    if (requireAdminScope && !scopes.includes(ADMIN_SCOPE)) {
      throw new NotAuthorizedError(TokenErrorMessages.missingScope);
    }

    return { claims: claims as AccessTokenClaims, user, userPool };
  }

  private async decodeAccessTokenUnchecked(
    ctx: Context,
    token: string | undefined,
  ): Promise<VerifiedAccessToken> {
    const claims = token ? decodeObject(token) : null;
    if (!claims) {
      ctx.logger.info("Unable to decode token");
      throw new InvalidParameterError();
    }
    const userPool = await this.cognito.getUserPoolForClientId(
      ctx,
      claims.client_id,
    );
    const user = await userPool.getUserByUsername(
      ctx,
      String(claims.sub ?? claims.username ?? ""),
    );
    if (!user) throw new UserNotFoundError();
    return { claims: claims as AccessTokenClaims, user, userPool };
  }

  public async verifyRefreshToken(
    ctx: Context,
    token: string | undefined,
    clientId: string,
  ): Promise<VerifiedRefreshToken> {
    const userPool = await this.cognito.getUserPoolForClientId(ctx, clientId);

    if (!this.verifying) {
      const user = token
        ? await userPool.getUserByRefreshToken(ctx, token)
        : null;
      if (!user) throw new NotAuthorizedError();
      return {
        claims: (decodeObject(token ?? "") ?? {}) as RefreshTokenClaims,
        user,
        userPool,
      };
    }

    const invalid = () =>
      new NotAuthorizedError(TokenErrorMessages.invalidRefreshToken);
    const claims = token ? decodeObject(token) : null;
    if (!token || !claims || !signatureValid(token)) throw invalid();
    if (
      claims.token_use !== undefined ||
      typeof claims["cognito:username"] !== "string" ||
      claims.iss !== this.issuerFor(userPool) ||
      (claims.client_id !== undefined && claims.client_id !== clientId)
    ) {
      throw invalid();
    }

    if (
      typeof claims.exp === "number" &&
      claims.exp <= epochSeconds(this.clock.get())
    ) {
      throw new NotAuthorizedError(TokenErrorMessages.expiredRefreshToken);
    }

    const user = await userPool.getUserByUsername(
      ctx,
      claims["cognito:username"],
    );
    if (!user) {
      throw new NotAuthorizedError(TokenErrorMessages.userDoesNotExist);
    }
    if (!user.Enabled) {
      throw new NotAuthorizedError(TokenErrorMessages.userDisabled);
    }
    if (!(user.RefreshTokens ?? []).includes(token)) {
      throw new NotAuthorizedError(TokenErrorMessages.revokedRefreshToken);
    }

    return { claims: claims as RefreshTokenClaims, user, userPool };
  }

  public verifySecretHash(
    client: AppClient,
    usernames: readonly (string | undefined)[],
    secretHash: string | undefined,
  ): void {
    if (this.tokenConfig.CheckSecretHash === false) return;
    assertSecretHash(client, usernames, secretHash);
  }

  public verifyClientSecret(
    client: AppClient,
    clientSecret: string | undefined,
  ): void {
    if (this.tokenConfig.CheckSecretHash === false) return;
    assertClientSecret(client, clientSecret);
  }
}

/** SecretHash check for the operations that take it as a top-level parameter. */
export const verifyRequestSecretHash = async (
  ctx: Context,
  services: { cognito: CognitoService; tokenVerifier: TokenVerifier },
  clientId: string,
  username: string | undefined,
  secretHash: string | undefined,
): Promise<void> => {
  const client = await services.cognito.getAppClient(ctx, clientId);
  if (client) {
    services.tokenVerifier.verifySecretHash(client, [username], secretHash);
  }
};
