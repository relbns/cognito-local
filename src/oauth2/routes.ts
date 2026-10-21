import type { Application, Request, Response } from "express";
import { CognitoError, TokenErrorMessages, UserNotFoundError } from "../errors";
import type { Services } from "../services";
import type { AppClient } from "../services/appClient";
import type { Context } from "../services/context";
import { refreshTokens } from "../services/refreshTokens";
import { withRefreshTokenRevoked } from "../services/tokenRevocation";
import type { VerifiedAccessToken } from "../services/tokenVerifier";
import { attributeValue } from "../services/userPoolService";
import type { AuthorizationCodeStore } from "./authorizationCodeStore";
import { sendAuthorizationResponse } from "./authorizationResponse";
import { type IdentityProviderConfig, identityProvidersOf } from "./federation";
import { attachFederationRoutes, beginFederation } from "./federationRoutes";
import { FederationStore } from "./federationStore";
import {
  continueHostedLogin,
  HOSTED_LOGIN_MESSAGES,
  type HostedLoginContext,
  type HostedLoginForm,
  type HostedLoginOutcome,
  signInWithPassword,
} from "./hostedLogin";
import { loginForm, noticePage, stepPage } from "./hostedLoginPages";
import { HostedLoginStore } from "./hostedLoginStore";
import {
  type AuthorizeParams,
  buildErrorRedirect,
  COGNITO_PROVIDER,
  decideAuthorize,
  decideClientCredentials,
  includesIdToken,
  isClientAuthenticated,
  parseClientCredentials,
  parseClientMetadata,
  parseScopes,
  type ResourceServerScopes,
} from "./oauthRequest";
import { verifyS256 } from "./pkce";

function badRequest(res: Response, message: string) {
  res
    .status(400)
    .json({ error: "invalid_request", error_description: message });
}

function tokenError(res: Response, error: string, description?: string) {
  return res
    .status(400)
    .json(description ? { error, error_description: description } : { error });
}

async function findAppClient(
  services: Services,
  ctx: Context,
  clientId: string | undefined,
): Promise<AppClient | null> {
  if (!clientId) return null;
  try {
    return await services.cognito.getAppClient(ctx, clientId);
  } catch {
    return null;
  }
}

async function listFederatedProviders(
  services: Services,
  ctx: Context,
  params: AuthorizeParams,
): Promise<IdentityProviderConfig[]> {
  const wantsFederation =
    (params.identity_provider &&
      params.identity_provider !== COGNITO_PROVIDER) ||
    (!params.identity_provider && params.idp_identifier);
  if (!wantsFederation || !params.client_id) return [];
  const userPool = await services.cognito.getUserPoolForClientId(
    ctx,
    params.client_id,
  );
  return identityProvidersOf(userPool.options);
}

const userInfoErrorDescription = (message: string): string =>
  ({
    [TokenErrorMessages.expiredAccessToken]: "Access token is expired",
    [TokenErrorMessages.revokedAccessToken]: "Access token has been revoked",
    [TokenErrorMessages.userDisabled]: "User is disabled",
  })[message] ?? "Invalid access token";

export function attachOAuth2Routes(
  app: Application,
  services: Services,
  codeStore: AuthorizationCodeStore,
  federationStore: FederationStore = new FederationStore(),
  hostedLoginStore: HostedLoginStore = new HostedLoginStore(services.clock),
): void {
  attachFederationRoutes(app, services, codeStore, federationStore);

  const sendHtml = (res: Response, status: number, html: string) =>
    res.status(status).type("text/html").send(html);

  const renderOutcome = (
    ctx: Context,
    res: Response,
    login: HostedLoginContext,
    outcome: HostedLoginOutcome,
  ) => {
    switch (outcome.kind) {
      case "loginError":
        return sendHtml(
          res,
          200,
          loginForm({
            clientId: login.appClient.ClientId,
            redirectUri: login.redirectUri,
            responseType: login.flow.responseType,
            codeChallenge: login.flow.codeChallenge,
            codeChallengeMethod: login.flow.codeChallengeMethod,
            scope: login.scope,
            state: login.state ?? "",
            error: outcome.error,
          }),
        );
      case "step":
        return sendHtml(
          res,
          200,
          stepPage(outcome.sessionId, outcome.step, outcome.error),
        );
      case "signedIn":
        return sendAuthorizationResponse(ctx, res, services, codeStore, {
          appClient: login.appClient,
          userPool: login.userPool,
          user: outcome.user,
          redirectUri: login.redirectUri,
          state: login.state,
          flow: login.flow,
        });
    }
  };

  const formFields = (body: Record<string, unknown>): HostedLoginForm => {
    const field = (name: string) =>
      typeof body[name] === "string" ? body[name] : undefined;
    return {
      new_password: field("new_password"),
      confirm_password: field("confirm_password"),
      mfa_method: field("mfa_method"),
      code: field("code"),
    };
  };

  const continueLogin = async (
    ctx: Context,
    res: Response,
    sessionId: string,
    body: Record<string, unknown>,
  ) => {
    const expired = () =>
      sendHtml(res, 400, noticePage(HOSTED_LOGIN_MESSAGES.sessionExpired));
    const pending = hostedLoginStore.peek(sessionId);
    if (!pending) return expired();
    const appClient = await findAppClient(services, ctx, pending.clientId);
    let userPool: Awaited<ReturnType<typeof services.cognito.getUserPool>>;
    try {
      userPool = await services.cognito.getUserPool(ctx, pending.userPoolId);
    } catch {
      hostedLoginStore.delete(sessionId);
      return expired();
    }
    if (!appClient) {
      hostedLoginStore.delete(sessionId);
      return expired();
    }
    const login: HostedLoginContext = {
      userPool,
      appClient,
      redirectUri: pending.redirectUri,
      state: pending.state,
      scope: pending.scope,
      flow: pending.flow,
    };
    const outcome = await continueHostedLogin(
      ctx,
      services,
      hostedLoginStore,
      login,
      sessionId,
      pending,
      formFields(body),
    );
    return renderOutcome(ctx, res, login, outcome);
  };

  app.get("/oauth2/authorize", async (req: Request, res: Response) => {
    const params = req.query as AuthorizeParams;
    const ctx: Context = { logger: req.log };

    const appClient = await findAppClient(services, ctx, params.client_id);
    let providers: IdentityProviderConfig[] = [];
    try {
      providers = await listFederatedProviders(services, ctx, params);
    } catch {
      providers = [];
    }
    const decision = decideAuthorize(params, appClient, providers);

    switch (decision.kind) {
      case "reject":
        return badRequest(res, decision.description);
      case "redirectError":
        return res.redirect(
          buildErrorRedirect(
            params.redirect_uri ?? "",
            decision.error,
            decision.description,
            params.state,
          ),
        );
      case "federated": {
        const provider = providers.find(
          (p) => p.ProviderName === decision.providerName,
        );
        if (!appClient || !provider) {
          return badRequest(res, "Invalid identity provider");
        }
        return beginFederation(req, res, federationStore, {
          clientId: appClient.ClientId,
          userPoolId: appClient.UserPoolId,
          redirectUri: params.redirect_uri ?? "",
          state: params.state,
          provider,
          flow: decision,
        });
      }
      case "login":
        return res
          .status(200)
          .type("text/html")
          .send(
            loginForm({
              clientId: params.client_id ?? "",
              redirectUri: params.redirect_uri ?? "",
              responseType: decision.responseType,
              codeChallenge: decision.codeChallenge,
              codeChallengeMethod: decision.codeChallengeMethod,
              scope: params.scope ?? "",
              state: params.state ?? "",
            }),
          );
    }
  });

  app.post("/oauth2/authorize", async (req: Request, res: Response) => {
    const body = req.body as AuthorizeParams & {
      username?: string;
      password?: string;
      login_session?: unknown;
    };
    const ctx: Context = { logger: req.log };
    if (typeof body.login_session === "string") {
      return continueLogin(ctx, res, body.login_session, req.body);
    }
    const { client_id, redirect_uri, scope, state, username, password } = body;

    const appClient = await findAppClient(services, ctx, client_id);
    const decision = decideAuthorize(
      { ...body, identity_provider: undefined, idp_identifier: undefined },
      appClient,
    );
    if (decision.kind === "reject") {
      return badRequest(res, decision.description);
    }
    if (decision.kind === "redirectError") {
      return res.redirect(
        buildErrorRedirect(
          redirect_uri ?? "",
          decision.error,
          decision.description,
          state,
        ),
      );
    }
    if (decision.kind !== "login" || !appClient || !client_id) {
      return badRequest(res, "Invalid request");
    }
    if (!username || !password) {
      return badRequest(res, "Missing required fields");
    }

    let userPool: Awaited<
      ReturnType<typeof services.cognito.getUserPoolForClientId>
    >;
    try {
      userPool = await services.cognito.getUserPoolForClientId(ctx, client_id);
    } catch {
      return badRequest(res, "Invalid client_id");
    }

    const { kind: _, ...flow } = decision;
    const login: HostedLoginContext = {
      userPool,
      appClient,
      redirectUri: redirect_uri ?? "",
      state,
      scope: scope ?? "",
      flow,
    };
    const outcome = await signInWithPassword(
      ctx,
      services,
      hostedLoginStore,
      login,
      username,
      password,
    );
    return renderOutcome(ctx, res, login, outcome);
  });

  const clientCredentialsGrant = async (
    ctx: Context,
    res: Response,
    appClient: AppClient,
    body: Record<string, string>,
  ) => {
    if (!appClient.ClientSecret) return tokenError(res, "invalid_client");
    const clientMetadata = parseClientMetadata(body.aws_client_metadata);
    if (clientMetadata === null) {
      return tokenError(
        res,
        "invalid_request",
        "aws_client_metadata must be a JSON object",
      );
    }
    const userPool = await services.cognito.getUserPool(
      ctx,
      appClient.UserPoolId,
    );
    const decision = decideClientCredentials(
      appClient,
      body.scope,
      (userPool.options as { _resourceServers?: ResourceServerScopes[] })
        ._resourceServers ?? [],
    );
    if (decision.kind === "error") return tokenError(res, decision.error);

    const token = await services.tokenGenerator.generateClientCredentials(
      ctx,
      appClient,
      decision.scopes,
      clientMetadata,
    );
    return res.status(200).json({
      access_token: token.AccessToken,
      expires_in: token.ExpiresIn,
      token_type: token.TokenType,
    });
  };

  app.post("/oauth2/token", async (req: Request, res: Response) => {
    const body = req.body as Record<string, string>;
    const { grant_type } = body;

    const ctx: Context = { logger: req.log };

    if (
      grant_type !== "authorization_code" &&
      grant_type !== "refresh_token" &&
      grant_type !== "client_credentials"
    ) {
      return tokenError(
        res,
        "unsupported_grant_type",
        `Unsupported grant_type: ${grant_type}`,
      );
    }

    const credentials = parseClientCredentials(req.headers.authorization, body);
    if (credentials.conflict) {
      return tokenError(
        res,
        "invalid_client",
        "client_id in the body does not match the Authorization header",
      );
    }
    const client_id = credentials.clientId;
    if (!client_id) return badRequest(res, "Missing client_id");

    const appClient = await findAppClient(services, ctx, client_id);
    if (!appClient) {
      return tokenError(res, "invalid_client", "Unknown client");
    }
    if (!isClientAuthenticated(appClient, credentials.clientSecret)) {
      return tokenError(res, "invalid_client", "Client authentication failed");
    }

    if (grant_type === "client_credentials") {
      return clientCredentialsGrant(ctx, res, appClient, body);
    }

    if (grant_type === "authorization_code") {
      const { code, redirect_uri, code_verifier } = body;

      if (!code) return badRequest(res, "Missing code");
      if (!redirect_uri) return badRequest(res, "Missing redirect_uri");

      const stored = codeStore.consume(code);
      if (!stored) {
        return tokenError(
          res,
          "invalid_grant",
          "Authorization code expired or invalid",
        );
      }

      if (stored.clientId !== client_id) {
        return tokenError(res, "invalid_grant", "client_id mismatch");
      }
      if (stored.redirectUri !== redirect_uri) {
        return tokenError(res, "unauthorized_client", "invalid_redirect");
      }
      if (stored.codeChallenge) {
        if (!code_verifier) {
          return tokenError(res, "invalid_grant", "Missing code_verifier");
        }
        if (!verifyS256(code_verifier, stored.codeChallenge)) {
          return tokenError(
            res,
            "invalid_grant",
            "code_verifier does not match code_challenge",
          );
        }
      }

      const userPool = await services.cognito.getUserPool(
        ctx,
        stored.userPoolId,
      );
      const user = await userPool.getUserByUsername(ctx, stored.username);
      if (!user) {
        return tokenError(res, "invalid_grant", "User not found");
      }

      const scopes = parseScopes(stored.scope);
      const userGroups = await userPool.listUserGroupMembership(ctx, user);
      const tokens = await services.tokenGenerator.generate(
        ctx,
        user,
        userGroups,
        appClient,
        undefined,
        "HostedAuth",
        scopes,
      );

      await userPool.storeRefreshToken(ctx, tokens.RefreshToken, user);

      return res.status(200).json({
        access_token: tokens.AccessToken,
        ...(includesIdToken(scopes) ? { id_token: tokens.IdToken } : {}),
        refresh_token: tokens.RefreshToken,
        token_type: "Bearer",
        expires_in: tokens.ExpiresIn,
      });
    }

    const { refresh_token } = body;
    if (!refresh_token) return badRequest(res, "Missing refresh_token");

    let refreshed: Awaited<ReturnType<typeof refreshTokens>>;
    try {
      const verified = await services.tokenVerifier.verifyRefreshToken(
        ctx,
        refresh_token,
        client_id,
      );
      refreshed = await refreshTokens(ctx, services, appClient, verified);
    } catch (e) {
      if (e instanceof CognitoError) {
        return tokenError(res, "invalid_grant", e.message);
      }
      throw e;
    }
    const { tokens, scopes, refreshToken } = refreshed;

    return res.status(200).json({
      access_token: tokens.AccessToken,
      ...(includesIdToken(scopes) ? { id_token: tokens.IdToken } : {}),
      ...(refreshToken ? { refresh_token: refreshToken } : {}),
      token_type: "Bearer",
      expires_in: tokens.ExpiresIn,
    });
  });

  // GET /oauth2/userInfo — return OIDC claims for a valid access token
  app.get("/oauth2/userInfo", async (req: Request, res: Response) => {
    const ctx: Context = { logger: req.log };

    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "invalid_token" });
    }

    const token = authHeader.slice(7);

    let verified: VerifiedAccessToken;
    try {
      verified = await services.tokenVerifier.verifyAccessToken(ctx, token, {
        requireAdminScope: false,
      });
    } catch (e) {
      if (e instanceof UserNotFoundError) {
        return res.status(404).json({ error: "user_not_found" });
      }
      if (e instanceof CognitoError) {
        const description = userInfoErrorDescription(e.message);
        res.setHeader(
          "WWW-Authenticate",
          `Bearer error="invalid_token", error_description="${description}"`,
        );
        return res
          .status(401)
          .json({ error: "invalid_token", error_description: description });
      }
      throw e;
    }
    const { user, claims: decoded } = verified;

    const claims: Record<string, string | boolean> = {
      sub: attributeValue("sub", user.Attributes) ?? user.Username,
    };

    const scope = decoded.scope ?? "";
    const scopes = typeof scope === "string" ? scope.split(" ") : [];

    if (scopes.includes("email") || scopes.includes("openid")) {
      const email = attributeValue("email", user.Attributes);
      if (email) claims.email = email;
      const emailVerified = attributeValue("email_verified", user.Attributes);
      if (emailVerified) claims.email_verified = emailVerified === "true";
    }

    if (scopes.includes("phone") || scopes.includes("openid")) {
      const phone = attributeValue("phone_number", user.Attributes);
      if (phone) claims.phone_number = phone;
      const phoneVerified = attributeValue(
        "phone_number_verified",
        user.Attributes,
      );
      if (phoneVerified) {
        claims.phone_number_verified = phoneVerified === "true";
      }
    }

    if (scopes.includes("profile")) {
      for (const attr of [
        "name",
        "family_name",
        "given_name",
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
      ]) {
        const val = attributeValue(attr, user.Attributes);
        if (val) claims[attr] = val;
      }
    }

    for (const attr of user.Attributes) {
      if (attr.Name.startsWith("custom:") && attr.Value !== undefined) {
        claims[attr.Name] = attr.Value;
      }
    }

    claims.username = user.Username;

    return res.status(200).json(claims);
  });

  // POST /oauth2/revoke — revoke a refresh token
  app.post("/oauth2/revoke", async (req: Request, res: Response) => {
    const ctx: Context = { logger: req.log };
    const body = req.body as Record<string, string>;
    const { token } = body;
    const credentials = parseClientCredentials(req.headers.authorization, body);
    const client_id = credentials.clientId;

    if (!token || !client_id) {
      return badRequest(res, "Missing token or client_id");
    }

    const appClient = await services.cognito.getAppClient(ctx, client_id);
    if (!appClient) {
      return res
        .status(400)
        .json({ error: "invalid_client", error_description: "Unknown client" });
    }

    // Confidential clients must authenticate before revoking tokens.
    if (
      credentials.conflict ||
      !isClientAuthenticated(appClient, credentials.clientSecret)
    ) {
      return res.status(401).json({ error: "invalid_client" });
    }

    const userPool = await services.cognito.getUserPoolForClientId(
      ctx,
      client_id,
    );
    const user = await userPool.getUserByRefreshToken(ctx, token);
    if (user) {
      await userPool.updateUser(ctx, user, (latest) =>
        withRefreshTokenRevoked(latest, token),
      );
    }

    return res.status(200).json({});
  });

  // GET /logout — redirect to a registered logout URI (hosted UI logout)
  app.get("/logout", async (req: Request, res: Response) => {
    const ctx: Context = { logger: req.log };
    const { client_id, logout_uri } = req.query as Record<string, string>;

    if (!client_id || !logout_uri) {
      return badRequest(res, "Missing client_id or logout_uri");
    }

    const appClient = await services.cognito.getAppClient(ctx, client_id);
    if (!appClient) {
      return res
        .status(400)
        .json({ error: "invalid_client", error_description: "Unknown client" });
    }

    if (
      appClient.LogoutURLs?.length &&
      !appClient.LogoutURLs.includes(logout_uri)
    ) {
      return badRequest(res, "logout_uri not registered");
    }

    return res.redirect(logout_uri);
  });
}
