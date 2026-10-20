import type { Application, Request, Response } from "express";
import * as jwt from "jsonwebtoken";
import PublicKey from "../keys/cognitoLocal.public.json";
import type { Services } from "../services";
import type { AppClient } from "../services/appClient";
import type { Context } from "../services/context";
import { attributeValue } from "../services/userPoolService";
import type { AuthorizationCodeStore } from "./authorizationCodeStore";
import { sendAuthorizationResponse } from "./authorizationResponse";
import { type IdentityProviderConfig, identityProvidersOf } from "./federation";
import { attachFederationRoutes, beginFederation } from "./federationRoutes";
import { FederationStore } from "./federationStore";
import { escapeHtml, hiddenInput } from "./html";
import {
  type AuthorizeParams,
  buildErrorRedirect,
  COGNITO_PROVIDER,
  decideAuthorize,
  includesIdToken,
  isClientAuthenticated,
  parseClientCredentials,
  parseScopes,
} from "./oauthRequest";
import { verifyS256 } from "./pkce";

const LOGIN_FORM = (params: {
  clientId: string;
  redirectUri: string;
  responseType: string;
  codeChallenge: string | undefined;
  codeChallengeMethod: string | undefined;
  scope: string;
  state: string;
  error?: string;
}) => `<!DOCTYPE html>
<html>
<head><title>Sign in</title></head>
<body>
${params.error ? `<p style="color:red">${escapeHtml(params.error)}</p>` : ""}
<form method="POST" action="/oauth2/authorize">
${hiddenInput("client_id", params.clientId)}${hiddenInput("redirect_uri", params.redirectUri)}${hiddenInput("response_type", params.responseType)}${hiddenInput("code_challenge", params.codeChallenge)}${hiddenInput("code_challenge_method", params.codeChallengeMethod)}${hiddenInput("scope", params.scope)}${hiddenInput("state", params.state)}  <label>Username: <input type="text" name="username" /></label><br />
  <label>Password: <input type="password" name="password" /></label><br />
  <button type="submit">Sign in</button>
</form>
</body>
</html>`;

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

function refreshTokenScopes(refreshToken: string): string[] {
  const decoded = jwt.decode(refreshToken);
  if (!decoded || typeof decoded !== "object") return [];
  return typeof decoded.scope === "string" ? parseScopes(decoded.scope) : [];
}

export function attachOAuth2Routes(
  app: Application,
  services: Services,
  codeStore: AuthorizationCodeStore,
  federationStore: FederationStore = new FederationStore(),
): void {
  attachFederationRoutes(app, services, codeStore, federationStore);

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
            LOGIN_FORM({
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
    };
    const { client_id, redirect_uri, scope, state, username, password } = body;
    const ctx: Context = { logger: req.log };

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

    const user = await userPool.getUserByUsername(ctx, username);

    if (
      !user ||
      user.Password !== password ||
      user.UserStatus === "UNCONFIRMED"
    ) {
      res
        .status(200)
        .type("text/html")
        .send(
          LOGIN_FORM({
            clientId: client_id,
            redirectUri: redirect_uri ?? "",
            responseType: decision.responseType,
            codeChallenge: decision.codeChallenge,
            codeChallengeMethod: decision.codeChallengeMethod,
            scope: scope ?? "",
            state: state ?? "",
            error: "Incorrect username or password.",
          }),
        );
      return;
    }

    return sendAuthorizationResponse(ctx, res, services, codeStore, {
      appClient,
      userPool,
      user,
      redirectUri: redirect_uri ?? "",
      state,
      flow: decision,
    });
  });

  app.post("/oauth2/token", async (req: Request, res: Response) => {
    const body = req.body as Record<string, string>;
    const { grant_type } = body;

    const ctx: Context = { logger: req.log };

    if (grant_type !== "authorization_code" && grant_type !== "refresh_token") {
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
        expires_in: 3600,
      });
    }

    const { refresh_token } = body;
    if (!refresh_token) return badRequest(res, "Missing refresh_token");

    const userPool = await services.cognito.getUserPoolForClientId(
      ctx,
      client_id,
    );
    const user = await userPool.getUserByRefreshToken(ctx, refresh_token);
    if (!user) {
      return tokenError(res, "invalid_grant", "Invalid refresh token");
    }

    const scopes = refreshTokenScopes(refresh_token);
    const userGroups = await userPool.listUserGroupMembership(ctx, user);
    const tokens = await services.tokenGenerator.generate(
      ctx,
      user,
      userGroups,
      appClient,
      undefined,
      "RefreshTokens",
      scopes,
    );

    return res.status(200).json({
      access_token: tokens.AccessToken,
      ...(includesIdToken(scopes) ? { id_token: tokens.IdToken } : {}),
      token_type: "Bearer",
      expires_in: 3600,
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

    let decoded: jwt.JwtPayload;
    try {
      const verified = jwt.verify(token, PublicKey.pem, {
        algorithms: ["RS256"],
      });
      if (typeof verified !== "object" || verified === null) {
        return res.status(401).json({ error: "invalid_token" });
      }
      decoded = verified as jwt.JwtPayload;
    } catch {
      return res.status(401).json({ error: "invalid_token" });
    }

    // Cognito's userInfo endpoint only accepts access tokens, not ID tokens.
    if (decoded.token_use !== "access") {
      return res.status(401).json({ error: "invalid_token" });
    }

    const userPoolId = decoded.iss?.split("/").pop();
    if (!userPoolId) {
      return res.status(401).json({ error: "invalid_token" });
    }

    const userPool = await services.cognito.getUserPool(ctx, userPoolId);
    const user = await userPool.getUserByUsername(
      ctx,
      decoded["username"] ?? decoded.sub ?? "",
    );
    if (!user) {
      return res.status(404).json({ error: "user_not_found" });
    }

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
      await userPool.saveUser(ctx, {
        ...user,
        RefreshTokens: (user.RefreshTokens ?? []).filter((t) => t !== token),
      });
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
