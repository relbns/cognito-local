import { createHash, timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { ADMIN_UI_PATH, adminUrl, html, layout, withQuery } from "./html";

export const ADMIN_TOKEN_COOKIE = "cognito_local_admin";
export const ADMIN_TOKEN_ENV = "COGNITO_LOCAL_ADMIN_TOKEN";

const sha256 = (value: string) => createHash("sha256").update(value).digest();

const sameSecret = (given: string, expected: string): boolean =>
  timingSafeEqual(sha256(given), sha256(expected));

// The cookie holds a digest of the token, so the token itself never sits in the browser.
const cookieValueFor = (token: string): string =>
  createHash("sha256")
    .update(`cognito-local-admin:${token}`)
    .digest("base64url");

const readCookie = (req: Request, name: string): string | undefined => {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const idx = part.indexOf("=");
    if (idx > 0 && part.slice(0, idx).trim() === name) {
      return decodeURIComponent(part.slice(idx + 1).trim());
    }
  }
  return undefined;
};

const bearerOf = (req: Request): string | undefined => {
  const match = /^Bearer\s+(.+)$/i.exec(req.get("authorization") ?? "");
  return match?.[1].trim();
};

const cookieHeader = (req: Request, value: string, maxAge?: number) =>
  [
    `${ADMIN_TOKEN_COOKIE}=${value}`,
    `Path=${ADMIN_UI_PATH}`,
    "HttpOnly",
    "SameSite=Lax",
    ...(req.secure ? ["Secure"] : []),
    ...(maxAge === undefined ? [] : [`Max-Age=${maxAge}`]),
  ].join("; ");

const LOOPBACK_HOSTS = new Set(["localhost", "::1", "[::1]"]);

export const isLoopbackHost = (hostname: string | undefined): boolean =>
  !!hostname && (LOOPBACK_HOSTS.has(hostname) || /^127\./.test(hostname));

export const adminTokenWarning = (opts: {
  hostname: string | undefined;
  adminUi: boolean;
  token: string | undefined;
}): string | undefined =>
  opts.adminUi && !opts.token && !isLoopbackHost(opts.hostname)
    ? `The admin UI and its API have no token while listening on ${opts.hostname ?? "all interfaces"}: anyone who reaches this port can read and change users. Set AdminUIConfig.Token or ${ADMIN_TOKEN_ENV}.`
    : undefined;

const safeNext = (value: unknown): string =>
  typeof value === "string" &&
  value.startsWith(`${ADMIN_UI_PATH}`) &&
  !value.startsWith("//")
    ? value
    : ADMIN_UI_PATH;

const loginPage = (next: string, error?: string) =>
  layout({
    title: "Sign in",
    active: "pools",
    bare: true,
    flash: { error },
    body: html`<h1>Admin token required</h1>
<p class="sub">This emulator's admin UI is protected by a token (AdminUIConfig.Token or ${ADMIN_TOKEN_ENV}).</p>
<form class="panel" method="post" action="${adminUrl("login")}">
  <input type="hidden" name="next" value="${next}" />
  <div class="row">
    <label>Token<input type="password" name="token" autocomplete="current-password" autofocus required /></label>
    <button class="primary" type="submit">Sign in</button>
  </div>
</form>`,
  });

const sendLogin = (
  res: Response,
  next: string,
  error?: string,
  status = 200,
) => {
  res
    .status(status)
    .type("html")
    .set("Cache-Control", "no-store")
    .send(loginPage(next, error));
};

/** Requires the admin token on every admin route when one is configured. */
export const adminAuth = (token: string | undefined) => {
  if (!token) {
    return (_req: Request, _res: Response, next: NextFunction) => next();
  }
  const cookie = cookieValueFor(token);

  return (req: Request, res: Response, next: NextFunction) => {
    res.locals.adminTokenRequired = true;
    const original = `${req.baseUrl}${req.url === "/" ? "" : req.url}`;

    if (req.path === "/login") {
      if (req.method === "POST") {
        const given = typeof req.body?.token === "string" ? req.body.token : "";
        const target = safeNext(req.body?.next);
        if (!sameSecret(given, token)) {
          sendLogin(res, target, "That token is not correct.", 401);
          return;
        }
        res.setHeader("Set-Cookie", cookieHeader(req, cookie));
        res.redirect(303, target);
        return;
      }
      sendLogin(res, safeNext(req.query.next));
      return;
    }
    if (req.path === "/logout" && req.method === "POST") {
      res.setHeader("Set-Cookie", cookieHeader(req, "", 0));
      res.redirect(303, adminUrl("login"));
      return;
    }

    const bearer = bearerOf(req);
    const fromCookie = readCookie(req, ADMIN_TOKEN_COOKIE);
    if (
      (bearer !== undefined && sameSecret(bearer, token)) ||
      (fromCookie !== undefined && sameSecret(fromCookie, cookie))
    ) {
      next();
      return;
    }

    const isApi = req.path.startsWith("/api/");
    const queryToken = req.query.token;
    if (!isApi && req.method === "GET" && typeof queryToken === "string") {
      const url = new URL(original, "http://admin.local");
      url.searchParams.delete("token");
      const target = `${url.pathname}${url.search}`;
      if (!sameSecret(queryToken, token)) {
        sendLogin(res, target, "That token is not correct.", 401);
        return;
      }
      res.setHeader("Set-Cookie", cookieHeader(req, cookie));
      res.redirect(303, target);
      return;
    }

    if (isApi || req.method !== "GET") {
      res
        .status(401)
        .set("WWW-Authenticate", 'Bearer realm="cognito-local admin"')
        .json({
          error: `The admin API needs the admin token as "Authorization: Bearer <token>".`,
        });
      return;
    }
    res.redirect(303, withQuery(adminUrl("login"), { next: original }));
  };
};
