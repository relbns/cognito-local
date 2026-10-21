import type { Application, Request, Response } from "express";
import { CognitoError, TokenErrorMessages, UserNotFoundError } from "../errors";
import type { Services } from "../services";
import { type AppClient, readableAttributes } from "../services/appClient";
import { type Context, requestContext } from "../services/context";
import { refreshTokens } from "../services/refreshTokens";
import { withRefreshTokenRevoked } from "../services/tokenRevocation";
import type { VerifiedAccessToken } from "../services/tokenVerifier";
import { attributeValue } from "../services/userPoolService";
import type { AuthorizationCodeStore } from "./authorizationCodeStore";
import { sendAuthorizationResponse } from "./authorizationResponse";
import {
  BrowserSessionStore,
  endBrowserSession,
  readSessionCookie,
  startBrowserSession,
} from "./browserSession";
import { type IdentityProviderConfig, identityProvidersOf } from "./federation";
import { attachFederationRoutes, beginFederation } from "./federationRoutes";
import { FederationStore } from "./federationStore";
import {
  continueHostedLogin,
  HOSTED_LOGIN_MESSAGES,
  type HostedLoginContext,
  type HostedLoginForm,
  type HostedLoginOutcome,
  signInWithPasskey,
  signInWithPassword,
} from "./hostedLogin";
import {
  loginForm,
  noticePage,
  oauthParamsOf,
  stepPage,
} from "./hostedLoginPages";
import { HostedLoginStore } from "./hostedLoginStore";
import { signUpAllowed } from "./hostedPages";
import {
  attachHostedPageRoutes,
  restoreHostedLogin,
} from "./hostedPagesRoutes";
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
  parsePrompt,
  parseScopes,
  type ResourceServerScopes,
} from "./oauthRequest";
import { attachPasskeyRoutes, passkeyLoginAllowed } from "./passkeyRoutes";
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
  browserSessions: BrowserSessionStore = new BrowserSessionStore(
    services.clock,
  ),
): void {
  attachFederationRoutes(
    app,
    services,
    codeStore,
    federationStore,
    (req, res, userPoolId, username) =>
      startBrowserSession(req, res, browserSessions, userPoolId, username),
  );

  const sendHtml = (res: Response, status: number, html: string) =>
    res.status(status).type("text/html").send(html);

  const findClient = (ctx: Context, clientId: string | undefined) =>
    findAppClient(services, ctx, clientId);

  const loginPageOptions = async (ctx: Context, userPoolId: string) => {
    try {
      const userPool = await services.cognito.getUserPool(ctx, userPoolId);
      return {
        signUpAllowed: signUpAllowed(userPool.options),
        passkeyAllowed: passkeyLoginAllowed(userPool.options),
      };
    } catch {
      return { signUpAllowed: true, passkeyAllowed: false };
    }
  };

  const renderOutcome = (
    ctx: Context,
    req: Request,
    res: Response,
    login: HostedLoginContext,
    outcome: HostedLoginOutcome,
  ) => {
    switch (outcome.kind) {
      case "loginError":
      case "loginNotice":
        return sendHtml(
          res,
          200,
          loginForm({
            ...oauthParamsOf(login),
            signUpAllowed: signUpAllowed(login.userPool.options),
            passkeyAllowed: passkeyLoginAllowed(login.userPool.options),
            ...(outcome.kind === "loginError"
              ? { error: outcome.error }
              : { notice: outcome.notice }),
          }),
        );
      case "step":
        return sendHtml(
          res,
          200,
          stepPage(outcome.sessionId, outcome.step, outcome.error),
        );
      case "signedIn":
        startBrowserSession(
          req,
          res,
          browserSessions,
          login.userPool.options.Id,
          outcome.user.Username,
        );
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
      credential: field("credential"),
    };
  };

  const continueLogin = async (
    ctx: Context,
    req: Request,
    res: Response,
    sessionId: string,
    body: Record<string, unknown>,
  ) => {
    const restored = await restoreHostedLogin(
      services,
      { store: hostedLoginStore, findAppClient: findClient },
      ctx,
      sessionId,
      ["newPassword", "selectMfa", "smsMfa", "totpMfa", "mfaSetup", "passkey"],
    );
    if (!restored) {
      return sendHtml(
        res,
        400,
        noticePage(HOSTED_LOGIN_MESSAGES.sessionExpired),
      );
    }
    const { login, pending } = restored;
    const outcome = await continueHostedLogin(
      ctx,
      services,
      hostedLoginStore,
      login,
      sessionId,
      pending,
      formFields(body),
    );
    return renderOutcome(ctx, req, res, login, outcome);
  };

  const sessionUser = async (
    ctx: Context,
    req: Request,
    appClient: AppClient,
  ) => {
    const signIn = browserSessions.find(
      readSessionCookie(req),
      appClient.UserPoolId,
    );
    if (!signIn) return null;
    try {
      const userPool = await services.cognito.getUserPool(
        ctx,
        appClient.UserPoolId,
      );
      const user = await userPool.getUserByUsername(ctx, signIn.username);
      return user?.Enabled ? { userPool, user } : null;
    } catch {
      return null;
    }
  };

  const authorize = async (req: Request, res: Response) => {
    const params = req.query as AuthorizeParams;
    const ctx = requestContext(req, services.config?.TokenConfig);

    const appClient = await findAppClient(services, ctx, params.client_id);
    let providers: IdentityProviderConfig[] = [];
    try {
      providers = await listFederatedProviders(services, ctx, params);
    } catch {
      providers = [];
    }
    const decision = decideAuthorize(params, appClient, providers);

    if (decision.kind === "reject") {
      return badRequest(res, decision.description);
    }
    if (decision.kind === "redirectError") {
      return res.redirect(
        buildErrorRedirect(
          params.redirect_uri ?? "",
          decision.error,
          decision.description,
          params.state,
        ),
      );
    }
    if (!appClient) return badRequest(res, "Invalid client_id");

    const prompt = parsePrompt(params.prompt);
    const reuseSession =
      !prompt.includes("login") &&
      (decision.kind === "login" || prompt.includes("none"));
    const session = reuseSession
      ? await sessionUser(ctx, req, appClient)
      : null;
    const { kind: _, ...flow } = decision;
    if (session) {
      return sendAuthorizationResponse(ctx, res, services, codeStore, {
        appClient,
        userPool: session.userPool,
        user: session.user,
        redirectUri: params.redirect_uri ?? "",
        state: params.state,
        flow,
      });
    }
    if (prompt.includes("none")) {
      return res.redirect(
        buildErrorRedirect(
          params.redirect_uri ?? "",
          "login_required",
          "",
          params.state,
        ),
      );
    }

    if (decision.kind === "federated") {
      const provider = providers.find(
        (p) => p.ProviderName === decision.providerName,
      );
      if (!provider) return badRequest(res, "Invalid identity provider");
      return beginFederation(req, res, federationStore, {
        clientId: appClient.ClientId,
        userPoolId: appClient.UserPoolId,
        redirectUri: params.redirect_uri ?? "",
        state: params.state,
        provider,
        flow: decision,
      });
    }
    return sendHtml(
      res,
      200,
      loginForm({
        clientId: params.client_id ?? "",
        redirectUri: params.redirect_uri ?? "",
        responseType: decision.responseType,
        codeChallenge: decision.codeChallenge,
        codeChallengeMethod: decision.codeChallengeMethod,
        scope: params.scope ?? "",
        state: params.state ?? "",
        ...(await loginPageOptions(ctx, appClient.UserPoolId)),
      }),
    );
  };

  attachHostedPageRoutes(app, services, {
    store: hostedLoginStore,
    findAppClient: findClient,
    renderOutcome,
  });
  attachPasskeyRoutes(app, services, {
    findAppClient: findClient,
    sessionUser,
  });

  app.get("/oauth2/authorize", authorize);
  app.get("/login", authorize);

  app.post("/oauth2/authorize", async (req: Request, res: Response) => {
    const body = req.body as AuthorizeParams & {
      username?: string;
      password?: string;
      passkey?: string;
      login_session?: unknown;
    };
    const ctx = requestContext(req, services.config?.TokenConfig);
    if (typeof body.login_session === "string") {
      return continueLogin(ctx, req, res, body.login_session, req.body);
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
    const withPasskey = body.passkey === "true";
    if (!withPasskey && (!username || !password)) {
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
    const outcome = withPasskey
      ? await signInWithPasskey(
          ctx,
          services,
          hostedLoginStore,
          login,
          username ?? "",
        )
      : await signInWithPassword(
          ctx,
          services,
          hostedLoginStore,
          login,
          username as string,
          password as string,
        );
    return renderOutcome(ctx, req, res, login, outcome);
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

    const ctx = requestContext(req, services.config?.TokenConfig);

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
    const ctx = requestContext(req, services.config?.TokenConfig);

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
    const client = await findAppClient(services, ctx, decoded.client_id);
    const attributes = readableAttributes(client, user.Attributes);

    const claims: Record<string, string | boolean> = {
      sub: attributeValue("sub", attributes) ?? user.Username,
    };

    const scope = decoded.scope ?? "";
    const scopes = typeof scope === "string" ? scope.split(" ") : [];

    if (scopes.includes("email") || scopes.includes("openid")) {
      const email = attributeValue("email", attributes);
      if (email) claims.email = email;
      const emailVerified = attributeValue("email_verified", attributes);
      if (emailVerified) claims.email_verified = emailVerified === "true";
    }

    if (scopes.includes("phone") || scopes.includes("openid")) {
      const phone = attributeValue("phone_number", attributes);
      if (phone) claims.phone_number = phone;
      const phoneVerified = attributeValue("phone_number_verified", attributes);
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
        const val = attributeValue(attr, attributes);
        if (val) claims[attr] = val;
      }
    }

    for (const attr of attributes) {
      if (attr.Name.startsWith("custom:") && attr.Value !== undefined) {
        claims[attr.Name] = attr.Value;
      }
    }

    claims.username = user.Username;

    return res.status(200).json(claims);
  });

  // POST /oauth2/revoke — revoke a refresh token
  app.post("/oauth2/revoke", async (req: Request, res: Response) => {
    const ctx = requestContext(req, services.config?.TokenConfig);
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

  // GET /logout: end the browser session, then go to logout_uri or back to the login page
  app.get("/logout", async (req: Request, res: Response) => {
    const ctx = requestContext(req, services.config?.TokenConfig);
    const query = req.query as Record<string, string | undefined>;
    const { client_id, logout_uri, redirect_uri } = query;

    if (!client_id) return badRequest(res, "Missing client_id");
    const appClient = await findAppClient(services, ctx, client_id);
    if (!appClient) {
      return res
        .status(400)
        .json({ error: "invalid_client", error_description: "Unknown client" });
    }

    let destination: string;
    if (logout_uri) {
      if (!(appClient.LogoutURLs ?? []).includes(logout_uri)) {
        return badRequest(
          res,
          "redirect_mismatch: logout_uri is not registered for this client",
        );
      }
      destination = logout_uri;
    } else if (redirect_uri) {
      if (!(appClient.CallbackURLs ?? []).includes(redirect_uri)) {
        return badRequest(
          res,
          "redirect_mismatch: redirect_uri is not registered for this client",
        );
      }
      if (!query.response_type) {
        return badRequest(res, "Missing response_type");
      }
      const login = new URLSearchParams();
      for (const name of [
        "client_id",
        "response_type",
        "redirect_uri",
        "state",
        "scope",
        "nonce",
      ]) {
        const value = query[name];
        if (typeof value === "string") login.set(name, value);
      }
      destination = `/login?${login}`;
    } else {
      return badRequest(res, "Missing logout_uri or redirect_uri");
    }

    endBrowserSession(req, res, browserSessions, appClient.UserPoolId);
    return res.redirect(destination);
  });
}
