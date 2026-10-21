import type { Application, Request, Response } from "express";
import { CognitoError } from "../errors";
import type { Services, UserPoolService } from "../services";
import type { AppClient } from "../services/appClient";
import { type Context, requestContext } from "../services/context";
import {
  completePasskeyRegistration,
  startPasskeyRegistration,
} from "../services/passkeys";
import type { User, UserPool } from "../services/userPoolService";
import { relyingPartyId, webAuthnEnabled } from "../services/webAuthn";
import {
  hostedPageUrl,
  noticePage,
  passkeyRegistrationPage,
} from "./hostedLoginPages";

export const PASSKEY_PAGE_MESSAGES = {
  invalidRequest: "The client_id or redirect_uri is not valid.",
  signInFirst: "Sign in before adding a passkey.",
} as const;

/** The login page offers passkey sign-in when the pool allows WEB_AUTHN and has a relying party. */
export const passkeyLoginAllowed = (pool: UserPool): boolean =>
  webAuthnEnabled(pool) && relyingPartyId(pool) !== undefined;

interface PasskeyRouteDeps {
  findAppClient: (
    ctx: Context,
    clientId: string | undefined,
  ) => Promise<AppClient | null>;
  sessionUser: (
    ctx: Context,
    req: Request,
    appClient: AppClient,
  ) => Promise<{ userPool: UserPoolService; user: User } | null>;
}

const field = (source: unknown, name: string): string | undefined => {
  const value = (source as Record<string, unknown> | undefined)?.[name];
  return typeof value === "string" ? value : undefined;
};

/** The managed login page that registers a passkey for the user signed in to this browser: /passkeys/add. */
export function attachPasskeyRoutes(
  app: Application,
  services: Services,
  deps: PasskeyRouteDeps,
): void {
  const sendHtml = (res: Response, status: number, html: string) =>
    res.status(status).type("text/html").send(html);

  const resolve = async (ctx: Context, req: Request, source: unknown) => {
    const clientId = field(source, "client_id");
    const redirectUri = field(source, "redirect_uri");
    const appClient = await deps.findAppClient(ctx, clientId);
    if (
      !appClient ||
      !redirectUri ||
      !(appClient.CallbackURLs ?? []).includes(redirectUri)
    ) {
      return { error: PASSKEY_PAGE_MESSAGES.invalidRequest } as const;
    }
    const session = await deps.sessionUser(ctx, req, appClient);
    return { appClient, redirectUri, session } as const;
  };

  const renderRegistration = async (
    ctx: Context,
    res: Response,
    appClient: AppClient,
    redirectUri: string,
    session: { userPool: UserPoolService; user: User },
    error?: string,
  ) => {
    const options = await startPasskeyRegistration(ctx, {
      userPool: session.userPool,
      user: session.user,
      clientId: appClient.ClientId,
      clock: services.clock,
    });
    return sendHtml(
      res,
      200,
      passkeyRegistrationPage({
        clientId: appClient.ClientId,
        redirectUri,
        username: session.user.Username,
        options,
        error,
      }),
    );
  };

  const signInFirst = (
    res: Response,
    appClient: AppClient,
    redirectUri: string,
  ) =>
    sendHtml(
      res,
      401,
      noticePage(PASSKEY_PAGE_MESSAGES.signInFirst, {
        href: hostedPageUrl("/login", {
          clientId: appClient.ClientId,
          redirectUri,
          responseType: "code",
          codeChallenge: undefined,
          codeChallengeMethod: undefined,
          scope: "",
          state: "",
        }),
        text: "Sign in",
      }),
    );

  app.get("/passkeys/add", async (req: Request, res: Response) => {
    const ctx = requestContext(req, services.config?.TokenConfig);
    const resolved = await resolve(ctx, req, req.query);
    if (resolved.error) {
      return sendHtml(res, 400, noticePage(resolved.error));
    }
    const { appClient, redirectUri, session } = resolved;
    if (!session) return signInFirst(res, appClient, redirectUri);
    try {
      return await renderRegistration(
        ctx,
        res,
        appClient,
        redirectUri,
        session,
      );
    } catch (e) {
      if (e instanceof CognitoError) {
        return sendHtml(res, 400, noticePage(e.message));
      }
      throw e;
    }
  });

  app.post("/passkeys/add", async (req: Request, res: Response) => {
    const ctx = requestContext(req, services.config?.TokenConfig);
    const resolved = await resolve(ctx, req, req.body);
    if (resolved.error) {
      return sendHtml(res, 400, noticePage(resolved.error));
    }
    const { appClient, redirectUri, session } = resolved;
    if (!session) return signInFirst(res, appClient, redirectUri);
    try {
      await completePasskeyRegistration(ctx, {
        userPool: session.userPool,
        user: session.user,
        clientId: appClient.ClientId,
        credential: field(req.body, "credential") || undefined,
        clock: services.clock,
      });
    } catch (e) {
      if (!(e instanceof CognitoError)) throw e;
      const latest =
        (await session.userPool.getUserByUsername(
          ctx,
          session.user.Username,
        )) ?? session.user;
      try {
        return await renderRegistration(
          ctx,
          res,
          appClient,
          redirectUri,
          { ...session, user: latest },
          e.message,
        );
      } catch (again) {
        if (again instanceof CognitoError) {
          return sendHtml(res, 400, noticePage(again.message));
        }
        throw again;
      }
    }
    return res.redirect(redirectUri);
  });
}
