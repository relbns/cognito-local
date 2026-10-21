import type { Application, Request, Response } from "express";
import { CognitoError } from "../errors";
import type { Services, UserPoolService } from "../services";
import type { AppClient } from "../services/appClient";
import { type Context, requestContext } from "../services/context";
import { ConfirmForgotPassword } from "../targets/confirmForgotPassword";
import { ConfirmSignUp } from "../targets/confirmSignUp";
import { ForgotPassword } from "../targets/forgotPassword";
import { ResendConfirmationCode } from "../targets/resendConfirmationCode";
import { SignUp } from "../targets/signUp";
import {
  HOSTED_LOGIN_MESSAGES,
  type HostedLoginContext,
  type HostedLoginOutcome,
  signInAfterSignUp,
} from "./hostedLogin";
import {
  forgotPasswordPage,
  noticePage,
  oauthParamsOf,
  signUpPage,
  stepPage,
} from "./hostedLoginPages";
import {
  CODE_PAGE_VALIDITY_MS,
  type HostedLoginStep,
  type HostedLoginStepKind,
  type HostedLoginStore,
  type PendingHostedLogin,
} from "./hostedLoginStore";
import {
  HOSTED_PAGE_MESSAGES,
  secretHashFor,
  signUpAllowed,
  signUpAttributeFields,
  signUpAttributes,
  usernameField,
} from "./hostedPages";
import {
  type AuthorizeParams,
  buildErrorRedirect,
  decideAuthorize,
} from "./oauthRequest";

export interface HostedPageDeps {
  store: HostedLoginStore;
  findAppClient(
    ctx: Context,
    clientId: string | undefined,
  ): Promise<AppClient | null>;
  renderOutcome(
    ctx: Context,
    req: Request,
    res: Response,
    login: HostedLoginContext,
    outcome: HostedLoginOutcome,
  ): unknown;
}

type Form = Record<string, string | undefined>;

const formOf = (body: unknown): Form =>
  Object.fromEntries(
    Object.entries((body ?? {}) as Record<string, unknown>).map(([k, v]) => [
      k,
      typeof v === "string" ? v : undefined,
    ]),
  );

const sendHtml = (res: Response, status: number, html: string) =>
  res.status(status).type("text/html").send(html);

const badRequest = (res: Response, message: string) =>
  res
    .status(400)
    .json({ error: "invalid_request", error_description: message });

/** Rebuilds the login context of a pending hosted step from the server-side store. */
export const restoreHostedLogin = async (
  services: Services,
  deps: Pick<HostedPageDeps, "store" | "findAppClient">,
  ctx: Context,
  sessionId: string | undefined,
  kinds?: readonly HostedLoginStepKind[],
): Promise<{
  login: HostedLoginContext;
  pending: PendingHostedLogin;
} | null> => {
  const pending = deps.store.peek(sessionId);
  if (!pending || (kinds && !kinds.includes(pending.step.kind))) return null;
  const appClient = await deps.findAppClient(ctx, pending.clientId);
  let userPool: UserPoolService;
  try {
    userPool = await services.cognito.getUserPool(ctx, pending.userPoolId);
  } catch {
    deps.store.delete(sessionId);
    return null;
  }
  if (!appClient) {
    deps.store.delete(sessionId);
    return null;
  }
  return {
    pending,
    login: {
      userPool,
      appClient,
      redirectUri: pending.redirectUri,
      state: pending.state,
      scope: pending.scope,
      flow: pending.flow,
    },
  };
};

export function attachHostedPageRoutes(
  app: Application,
  services: Services,
  deps: HostedPageDeps,
): void {
  const { store, renderOutcome } = deps;
  const signUp = SignUp(services);
  const confirmSignUp = ConfirmSignUp(services);
  const resendCode = ResendConfirmationCode(services);
  const forgotPassword = ForgotPassword(services);
  const confirmForgotPassword = ConfirmForgotPassword(services);

  const expired = (res: Response) =>
    sendHtml(res, 400, noticePage(HOSTED_LOGIN_MESSAGES.sessionExpired));

  // The authorize parameters are checked again on every request, as the login form checks them.
  const resolveOAuth = async (
    ctx: Context,
    res: Response,
    params: AuthorizeParams,
  ): Promise<HostedLoginContext | null> => {
    const appClient = await deps.findAppClient(ctx, params.client_id);
    const decision = decideAuthorize(
      { ...params, identity_provider: undefined, idp_identifier: undefined },
      appClient,
    );
    if (decision.kind === "reject") {
      badRequest(res, decision.description);
      return null;
    }
    if (decision.kind === "redirectError") {
      res.redirect(
        buildErrorRedirect(
          params.redirect_uri ?? "",
          decision.error,
          decision.description,
          params.state,
        ),
      );
      return null;
    }
    if (decision.kind !== "login" || !appClient) {
      badRequest(res, "Invalid request");
      return null;
    }
    let userPool: UserPoolService;
    try {
      userPool = await services.cognito.getUserPool(ctx, appClient.UserPoolId);
    } catch {
      badRequest(res, "Invalid client_id");
      return null;
    }
    const { kind: _, ...flow } = decision;
    return {
      userPool,
      appClient,
      redirectUri: params.redirect_uri ?? "",
      state: params.state,
      scope: params.scope ?? "",
      flow,
    };
  };

  const internalUsername = async (
    ctx: Context,
    login: HostedLoginContext,
    username: string,
  ) =>
    (await login.userPool.getUserByUsername(ctx, username))?.Username ??
    username;

  const pendingStep = (
    login: HostedLoginContext,
    username: string,
    step: HostedLoginStep,
  ): string =>
    store.create(
      {
        userPoolId: login.userPool.options.Id,
        clientId: login.appClient.ClientId,
        username,
        redirectUri: login.redirectUri,
        state: login.state,
        scope: login.scope,
        flow: login.flow,
        step,
      },
      CODE_PAGE_VALIDITY_MS,
    );

  const renderSignUp = (
    res: Response,
    login: HostedLoginContext,
    values?: Form,
    error?: string,
  ) =>
    sendHtml(
      res,
      200,
      signUpPage({
        ...oauthParamsOf(login),
        usernameField: usernameField(login.userPool.options, "signUp"),
        attributeFields: signUpAttributeFields(login.userPool.options),
        values,
        error,
      }),
    );

  const renderForgot = (
    res: Response,
    login: HostedLoginContext,
    username?: string,
    error?: string,
  ) =>
    sendHtml(
      res,
      200,
      forgotPasswordPage({
        ...oauthParamsOf(login),
        usernameField: usernameField(login.userPool.options, "signIn"),
        username,
        error,
      }),
    );

  const refuseSignUp = (res: Response) =>
    sendHtml(res, 400, noticePage(HOSTED_PAGE_MESSAGES.signUpNotPermitted));

  app.get("/signup", async (req: Request, res: Response) => {
    const ctx = requestContext(req, services.config?.TokenConfig);
    const login = await resolveOAuth(ctx, res, req.query as AuthorizeParams);
    if (!login) return;
    if (!signUpAllowed(login.userPool.options)) return refuseSignUp(res);
    return renderSignUp(res, login);
  });

  app.post("/signup", async (req: Request, res: Response) => {
    const ctx = requestContext(req, services.config?.TokenConfig);
    const form = formOf(req.body);
    const login = await resolveOAuth(ctx, res, form as AuthorizeParams);
    if (!login) return;
    const pool = login.userPool.options;
    if (!signUpAllowed(pool)) return refuseSignUp(res);

    const username = form.username?.trim() ?? "";
    const values = { ...form, password: undefined };
    if (!username) {
      return renderSignUp(
        res,
        login,
        values,
        HOSTED_PAGE_MESSAGES.usernameRequired,
      );
    }
    if (!form.password) {
      return renderSignUp(
        res,
        login,
        values,
        HOSTED_PAGE_MESSAGES.passwordRequired,
      );
    }

    let result: Awaited<ReturnType<typeof signUp>>;
    try {
      result = await signUp(ctx, {
        ClientId: login.appClient.ClientId,
        Username: username,
        Password: form.password,
        UserAttributes: signUpAttributes(pool, username, form),
        SecretHash: secretHashFor(login.appClient, username),
      } as Parameters<typeof signUp>[1]);
    } catch (e) {
      if (e instanceof CognitoError) {
        return renderSignUp(res, login, values, e.message);
      }
      throw e;
    }

    const user = await login.userPool.getUserByUsername(ctx, username);
    if (!user) return expired(res);
    if (result.UserConfirmed) {
      const outcome = await signInAfterSignUp(
        ctx,
        services,
        store,
        login,
        user,
      );
      return renderOutcome(ctx, req, res, login, outcome);
    }
    if (!result.CodeDeliveryDetails) {
      return renderOutcome(ctx, req, res, login, {
        kind: "loginNotice",
        notice: HOSTED_PAGE_MESSAGES.awaitingConfirmation,
      });
    }
    const step: HostedLoginStep = {
      kind: "confirmSignUp",
      delivery: result.CodeDeliveryDetails,
      signInAfter: true,
    };
    return sendHtml(
      res,
      200,
      stepPage(pendingStep(login, user.Username, step), step),
    );
  });

  // A confirm link names the user; only the code proves the account, as with ConfirmSignUp.
  app.get("/confirm", async (req: Request, res: Response) => {
    const ctx = requestContext(req, services.config?.TokenConfig);
    const query = req.query as AuthorizeParams & { username?: unknown };
    const login = await resolveOAuth(ctx, res, query);
    if (!login) return;
    if (typeof query.username !== "string" || !query.username) {
      return badRequest(res, "Missing username");
    }
    const step: HostedLoginStep = {
      kind: "confirmSignUp",
      delivery: null,
      signInAfter: false,
    };
    const username = await internalUsername(ctx, login, query.username);
    return sendHtml(
      res,
      200,
      stepPage(pendingStep(login, username, step), step),
    );
  });

  app.post("/confirm", async (req: Request, res: Response) => {
    const ctx = requestContext(req, services.config?.TokenConfig);
    const form = formOf(req.body);
    const sessionId = form.login_session;
    const restored = await restoreHostedLogin(services, deps, ctx, sessionId, [
      "confirmSignUp",
    ]);
    if (!restored) return expired(res);
    const { login, pending } = restored;
    const step = pending.step as Extract<
      HostedLoginStep,
      { kind: "confirmSignUp" }
    >;
    const retry = (error: string) =>
      sendHtml(res, 200, stepPage(sessionId as string, step, error));

    const code = form.code?.trim();
    if (!code) return retry(HOSTED_PAGE_MESSAGES.codeRequired);
    try {
      await confirmSignUp(ctx, {
        ClientId: login.appClient.ClientId,
        Username: pending.username,
        ConfirmationCode: code,
        SecretHash: secretHashFor(login.appClient, pending.username),
      } as Parameters<typeof confirmSignUp>[1]);
    } catch (e) {
      if (e instanceof CognitoError) return retry(e.message);
      throw e;
    }
    store.delete(sessionId);

    const user = step.signInAfter
      ? await login.userPool.getUserByUsername(ctx, pending.username)
      : null;
    const outcome: HostedLoginOutcome = user
      ? await signInAfterSignUp(ctx, services, store, login, user)
      : { kind: "loginNotice", notice: HOSTED_PAGE_MESSAGES.accountConfirmed };
    return renderOutcome(ctx, req, res, login, outcome);
  });

  app.post("/resendcode", async (req: Request, res: Response) => {
    const ctx = requestContext(req, services.config?.TokenConfig);
    const sessionId = formOf(req.body).login_session;
    const restored = await restoreHostedLogin(services, deps, ctx, sessionId, [
      "confirmSignUp",
    ]);
    if (!restored) return expired(res);
    const { login, pending } = restored;
    const step = pending.step as Extract<
      HostedLoginStep,
      { kind: "confirmSignUp" }
    >;
    let resent: HostedLoginStep;
    try {
      const result = await resendCode(ctx, {
        ClientId: login.appClient.ClientId,
        Username: pending.username,
        SecretHash: secretHashFor(login.appClient, pending.username),
      } as Parameters<typeof resendCode>[1]);
      resent = { ...step, delivery: result.CodeDeliveryDetails ?? null };
    } catch (e) {
      if (e instanceof CognitoError) {
        return sendHtml(
          res,
          200,
          stepPage(sessionId as string, step, e.message),
        );
      }
      throw e;
    }
    store.delete(sessionId);
    return sendHtml(
      res,
      200,
      stepPage(
        pendingStep(login, pending.username, resent),
        resent,
        undefined,
        HOSTED_PAGE_MESSAGES.codeResent,
      ),
    );
  });

  app.get("/forgotPassword", async (req: Request, res: Response) => {
    const ctx = requestContext(req, services.config?.TokenConfig);
    const login = await resolveOAuth(ctx, res, req.query as AuthorizeParams);
    if (!login) return;
    return renderForgot(res, login);
  });

  app.post("/forgotPassword", async (req: Request, res: Response) => {
    const ctx = requestContext(req, services.config?.TokenConfig);
    const form = formOf(req.body);
    const login = await resolveOAuth(ctx, res, form as AuthorizeParams);
    if (!login) return;
    const username = form.username?.trim() ?? "";
    if (!username) {
      return renderForgot(
        res,
        login,
        username,
        HOSTED_PAGE_MESSAGES.usernameRequired,
      );
    }
    let result: Awaited<ReturnType<typeof forgotPassword>>;
    try {
      result = await forgotPassword(ctx, {
        ClientId: login.appClient.ClientId,
        Username: username,
        SecretHash: secretHashFor(login.appClient, username),
      } as Parameters<typeof forgotPassword>[1]);
    } catch (e) {
      if (e instanceof CognitoError) {
        return renderForgot(res, login, username, e.message);
      }
      throw e;
    }
    const step: HostedLoginStep = {
      kind: "confirmForgotPassword",
      delivery: result.CodeDeliveryDetails ?? null,
    };
    const internal = await internalUsername(ctx, login, username);
    return sendHtml(
      res,
      200,
      stepPage(pendingStep(login, internal, step), step),
    );
  });

  app.get("/confirmForgotPassword", async (req: Request, res: Response) => {
    const ctx = requestContext(req, services.config?.TokenConfig);
    const query = req.query as AuthorizeParams & { username?: unknown };
    const login = await resolveOAuth(ctx, res, query);
    if (!login) return;
    if (typeof query.username !== "string" || !query.username) {
      return renderForgot(res, login);
    }
    const step: HostedLoginStep = {
      kind: "confirmForgotPassword",
      delivery: null,
    };
    const username = await internalUsername(ctx, login, query.username);
    return sendHtml(
      res,
      200,
      stepPage(pendingStep(login, username, step), step),
    );
  });

  app.post("/confirmForgotPassword", async (req: Request, res: Response) => {
    const ctx = requestContext(req, services.config?.TokenConfig);
    const form = formOf(req.body);
    const sessionId = form.login_session;
    const restored = await restoreHostedLogin(services, deps, ctx, sessionId, [
      "confirmForgotPassword",
    ]);
    if (!restored) return expired(res);
    const { login, pending } = restored;
    const retry = (error: string) =>
      sendHtml(res, 200, stepPage(sessionId as string, pending.step, error));

    const code = form.code?.trim();
    const newPassword = form.new_password ?? "";
    if (!code) return retry(HOSTED_PAGE_MESSAGES.codeRequired);
    if (!newPassword) return retry(HOSTED_LOGIN_MESSAGES.newPasswordRequired);
    if (
      form.confirm_password !== undefined &&
      form.confirm_password !== newPassword
    ) {
      return retry(HOSTED_LOGIN_MESSAGES.passwordsDoNotMatch);
    }
    try {
      await confirmForgotPassword(ctx, {
        ClientId: login.appClient.ClientId,
        Username: pending.username,
        ConfirmationCode: code,
        Password: newPassword,
        SecretHash: secretHashFor(login.appClient, pending.username),
      } as Parameters<typeof confirmForgotPassword>[1]);
    } catch (e) {
      if (e instanceof CognitoError) return retry(e.message);
      throw e;
    }
    store.delete(sessionId);
    return renderOutcome(ctx, req, res, login, {
      kind: "loginNotice",
      notice: HOSTED_PAGE_MESSAGES.passwordReset,
    });
  });
}
