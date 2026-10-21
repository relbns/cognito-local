import bodyParser from "body-parser";
import express, { type Request, type Response } from "express";
import { CognitoError, ResourceNotFoundError } from "../errors";
import PublicKey from "../keys/cognitoLocal.public.json";
import {
  applySeed,
  exportSeed,
  formatSeedResult,
  SeedApplyError,
  SeedValidationError,
  summarizeSeedResult,
} from "../seed";
import { resolveSeedFileTargets } from "../seed/load";
import { assertValidSeed } from "../seed/validate";
import type { Router } from "../server/Router";
import type { Services } from "../services";
import type { CodeLogEntry } from "../services/codeLog";
import type { Context } from "../services/context";
import {
  attributeValue,
  type User,
  type UserPoolService,
} from "../services/userPoolService";
import { adminAuth } from "./auth";
import { createCallbackRouter } from "./callback";
import { adminUrl, type Flash, layout, type SafeHtml, withQuery } from "./html";
import { inspectToken } from "./tokens";
import {
  codesPage,
  errorPage,
  groupsPage,
  poolPage,
  poolsPage,
  tokensPage,
  userPage,
  usersPage,
} from "./views";

const ctxOf = (req: Request): Context => ({ logger: req.log });

const str = (value: unknown): string =>
  typeof value === "string" ? value.trim() : "";

const flashOf = (req: Request): Flash => ({
  ok: str(req.query.ok) || undefined,
  error: str(req.query.error) || undefined,
});

const send = (
  res: Response,
  title: string,
  active: "pools" | "codes" | "tokens" | "callback",
  body: SafeHtml,
  flash?: Flash,
  status = 200,
) => {
  res
    .status(status)
    .type("html")
    .set("Cache-Control", "no-store")
    .send(
      layout({
        title,
        active,
        body,
        flash,
        tokenRequired: !!res.locals.adminTokenRequired,
      }),
    );
};

const sendError = (res: Response, e: unknown) => {
  if (e instanceof ResourceNotFoundError) {
    send(res, "Not found", "pools", errorPage("Not found", e.message), {}, 404);
    return;
  }
  send(
    res,
    "Error",
    "pools",
    errorPage("Something went wrong", (e as Error)?.message ?? String(e)),
    {},
    500,
  );
};

const page =
  (handler: (req: Request, res: Response) => Promise<void>) =>
  async (req: Request, res: Response) => {
    try {
      await handler(req, res);
    } catch (e) {
      sendError(res, e);
    }
  };

const userMatches = (user: User, q: string) =>
  [
    user.Username,
    attributeValue("email", user.Attributes),
    attributeValue("phone_number", user.Attributes),
    attributeValue("sub", user.Attributes),
    attributeValue("preferred_username", user.Attributes),
  ].some((v) => v?.toLowerCase().includes(q));

const groupsByUser = async (ctx: Context, pool: UserPoolService) => {
  const map = new Map<string, string[]>();
  for (const group of await pool.listGroups(ctx)) {
    for (const member of group.members ?? []) {
      map.set(member, [...(map.get(member) ?? []), group.GroupName]);
    }
  }
  return map;
};

const parseAttributes = (text: string) =>
  text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const idx = line.indexOf("=");
      if (idx <= 0)
        throw new Error(`Attribute line "${line}" is not name=value`);
      return { Name: line.slice(0, idx).trim(), Value: line.slice(idx + 1) };
    });

export interface CodeFilters {
  pool: string;
  type: string;
  q: string;
}

export const filterCodes = (
  entries: readonly CodeLogEntry[],
  filters: CodeFilters,
) => {
  const q = filters.q.toLowerCase();
  return entries.filter(
    (e) =>
      (!filters.pool || e.userPoolId === filters.pool) &&
      (!filters.type || e.type === filters.type) &&
      (!q ||
        [e.username, e.email, e.phoneNumber, e.code].some((v) =>
          v?.toLowerCase().includes(q),
        )),
  );
};

export const createAdminRouter = (
  services: Services,
  router: Router,
): express.Router => {
  const admin = express.Router();
  admin.use(bodyParser.urlencoded({ extended: false }));

  // Blocks cross-site form posts from other pages open in the same browser.
  admin.use((req, res, next) => {
    if (req.method !== "POST") return next();
    const origin = req.get("origin");
    const crossSite =
      req.get("sec-fetch-site") === "cross-site" ||
      (!!origin &&
        origin !== "null" &&
        new URL(origin).host !== req.get("host"));
    if (crossSite) {
      res.status(403).type("text/plain").send("Cross-site request refused");
      return;
    }
    next();
  });

  admin.use(adminAuth(services.config.AdminUIConfig?.Token));

  const run = <T = unknown>(req: Request, target: string, body: unknown) =>
    router(target)(ctxOf(req), body) as Promise<T>;

  const action =
    (
      handler: (
        req: Request,
      ) => Promise<{ redirect: string; ok: string } | string>,
      back: (req: Request) => string,
    ) =>
    async (req: Request, res: Response) => {
      try {
        const result = await handler(req);
        const { redirect, ok } =
          typeof result === "string"
            ? { redirect: back(req), ok: result }
            : result;
        res.redirect(303, withQuery(redirect, { ok }));
      } catch (e) {
        const message =
          e instanceof CognitoError
            ? `${e.code}: ${e.message}`
            : ((e as Error)?.message ?? String(e));
        res.redirect(303, withQuery(back(req), { error: message }));
      }
    };

  const userBack = (req: Request) =>
    adminUrl("pools", req.params.poolId, "users", req.params.username);

  const enrichEntries = async (
    ctx: Context,
    entries: readonly CodeLogEntry[],
  ): Promise<CodeLogEntry[]> => {
    const cache = new Map<string, User | null>();
    const out: CodeLogEntry[] = [];
    for (const entry of entries) {
      if (entry.email || entry.phoneNumber) {
        out.push(entry);
        continue;
      }
      const key = `${entry.userPoolId}\u0000${entry.username}`;
      if (!cache.has(key)) {
        const user = await services.cognito
          .getUserPool(ctx, entry.userPoolId)
          .then((pool) => pool.getUserByUsername(ctx, entry.username))
          .catch(() => null);
        cache.set(key, user);
      }
      const user = cache.get(key);
      out.push({
        ...entry,
        email: attributeValue("email", user?.Attributes),
        phoneNumber: attributeValue("phone_number", user?.Attributes),
      });
    }
    return out;
  };

  const codeFilters = (req: Request): CodeFilters => ({
    pool: str(req.query.pool),
    type: str(req.query.type),
    q: str(req.query.q),
  });

  const sessionsFor = (filters: CodeFilters) => {
    const q = filters.q.toLowerCase();
    return services.authSessions
      .list()
      .filter(
        (s) =>
          (!filters.pool || s.session.userPoolId === filters.pool) &&
          (!filters.type || filters.type === "CUSTOM_AUTH") &&
          (!q || s.session.username.toLowerCase().includes(q)),
      );
  };

  admin.get(
    "/",
    page(async (req, res) => {
      const ctx = ctxOf(req);
      const pools = await services.cognito.listUserPools(ctx);
      const summaries = [];
      for (const pool of pools) {
        const service = await services.cognito.getUserPool(ctx, pool.Id);
        summaries.push({
          pool: service.options,
          users: (await service.listUsers(ctx)).length,
          clients: (await services.cognito.listAppClients(ctx, pool.Id)).length,
          groups: (await service.listGroups(ctx)).length,
        });
      }
      send(
        res,
        "User pools",
        "pools",
        poolsPage(summaries, {
          triggers: Object.keys(services.config.TriggerFunctions ?? {}),
          issuerDomain: services.config.TokenConfig?.IssuerDomain,
          authSessionValidityMinutes:
            services.config.AuthSessionConfig?.AuthSessionValidity,
          codeLogSize: services.config.AdminUIConfig?.CodeLogSize,
        }),
        flashOf(req),
      );
    }),
  );

  admin.get(
    "/pools/:poolId",
    page(async (req, res) => {
      const ctx = ctxOf(req);
      const pool = await services.cognito.getUserPool(ctx, req.params.poolId);
      send(
        res,
        pool.options.Name ?? pool.options.Id,
        "pools",
        poolPage({
          pool: pool.options,
          clients: await services.cognito.listAppClients(ctx, pool.options.Id),
          users: (await pool.listUsers(ctx)).length,
          groups: (await pool.listGroups(ctx)).length,
        }),
        flashOf(req),
      );
    }),
  );

  admin.get(
    "/pools/:poolId/users",
    page(async (req, res) => {
      const ctx = ctxOf(req);
      const pool = await services.cognito.getUserPool(ctx, req.params.poolId);
      const q = str(req.query.q);
      const status = str(req.query.status);
      const all = await pool.listUsers(ctx);
      const users = all.filter(
        (u) =>
          (!q || userMatches(u, q.toLowerCase())) &&
          (!status || u.UserStatus === status),
      );
      send(
        res,
        "Users",
        "pools",
        usersPage({
          pool: pool.options,
          users,
          total: all.length,
          groupsByUser: await groupsByUser(ctx, pool),
          groupCount: (await pool.listGroups(ctx)).length,
          q,
          status,
        }),
        flashOf(req),
      );
    }),
  );

  admin.post(
    "/pools/:poolId/users",
    action(
      async (req) => {
        const body = req.body as Record<string, string>;
        const username = str(body.username);
        const email = str(body.email);
        const phone = str(body.phone_number);
        const password = str(body.password);
        const verified = body.verified === "1";
        const send = body.send === "1";
        if (!username) throw new Error("Username is required");

        const attributes = [
          ...(email ? [{ Name: "email", Value: email }] : []),
          ...(email && verified
            ? [{ Name: "email_verified", Value: "true" }]
            : []),
          ...(phone ? [{ Name: "phone_number", Value: phone }] : []),
          ...(phone && verified
            ? [{ Name: "phone_number_verified", Value: "true" }]
            : []),
          ...parseAttributes(str(body.attributes)),
        ];

        const created = await run<{ User: { Username: string } }>(
          req,
          "AdminCreateUser",
          {
            UserPoolId: req.params.poolId,
            Username: username,
            UserAttributes: attributes,
            TemporaryPassword: password || undefined,
            MessageAction: send ? undefined : "SUPPRESS",
            DesiredDeliveryMediums: send
              ? [email ? "EMAIL" : "SMS"]
              : undefined,
          },
        );
        const createdUsername = created.User.Username;

        if (password && body.permanent === "1") {
          await run(req, "AdminSetUserPassword", {
            UserPoolId: req.params.poolId,
            Username: createdUsername,
            Password: password,
            Permanent: true,
          });
        }

        return {
          redirect: adminUrl(
            "pools",
            req.params.poolId,
            "users",
            createdUsername,
          ),
          ok: `Created user ${createdUsername}`,
        };
      },
      (req) => adminUrl("pools", req.params.poolId, "users"),
    ),
  );

  admin.get(
    "/pools/:poolId/users/:username",
    page(async (req, res) => {
      const ctx = ctxOf(req);
      const pool = await services.cognito.getUserPool(ctx, req.params.poolId);
      const user = await pool.getUserByUsername(ctx, req.params.username);
      if (!user) {
        throw new ResourceNotFoundError(
          `User ${req.params.username} not found in ${pool.options.Id}`,
        );
      }
      const recentCodes = (services.codeLog?.list() ?? []).filter(
        (e) => e.userPoolId === pool.options.Id && e.username === user.Username,
      );
      send(
        res,
        user.Username,
        "pools",
        userPage({
          pool: pool.options,
          user,
          groups: await pool.listUserGroupMembership(ctx, user),
          allGroups: await pool.listGroups(ctx),
          recentCodes,
        }),
        flashOf(req),
      );
    }),
  );

  const userTarget = (
    target: string,
    ok: string,
    extra?: (req: Request) => object,
  ) =>
    action(async (req) => {
      await run(req, target, {
        UserPoolId: req.params.poolId,
        Username: req.params.username,
        ...extra?.(req),
      });
      return ok;
    }, userBack);

  admin.post(
    "/pools/:poolId/users/:username/confirm",
    userTarget("AdminConfirmSignUp", "User confirmed"),
  );
  admin.post(
    "/pools/:poolId/users/:username/enable",
    userTarget("AdminEnableUser", "User enabled"),
  );
  admin.post(
    "/pools/:poolId/users/:username/disable",
    userTarget("AdminDisableUser", "User disabled"),
  );
  admin.post(
    "/pools/:poolId/users/:username/password",
    action(async (req) => {
      const password = str(req.body?.password);
      if (!password) throw new Error("Password is required");
      const permanent = req.body?.permanent === "1";
      await run(req, "AdminSetUserPassword", {
        UserPoolId: req.params.poolId,
        Username: req.params.username,
        Password: password,
        Permanent: permanent,
      });
      return permanent ? "Password set" : "Temporary password set";
    }, userBack),
  );
  admin.post(
    "/pools/:poolId/users/:username/groups/add",
    action(async (req) => {
      const group = str(req.body?.group);
      await run(req, "AdminAddUserToGroup", {
        UserPoolId: req.params.poolId,
        Username: req.params.username,
        GroupName: group,
      });
      return `Added to ${group}`;
    }, userBack),
  );
  admin.post(
    "/pools/:poolId/users/:username/groups/remove",
    action(async (req) => {
      const group = str(req.body?.group);
      await run(req, "AdminRemoveUserFromGroup", {
        UserPoolId: req.params.poolId,
        Username: req.params.username,
        GroupName: group,
      });
      return `Removed from ${group}`;
    }, userBack),
  );
  admin.post(
    "/pools/:poolId/users/:username/delete",
    action(async (req) => {
      await run(req, "AdminDeleteUser", {
        UserPoolId: req.params.poolId,
        Username: req.params.username,
      });
      return {
        redirect: adminUrl("pools", req.params.poolId, "users"),
        ok: `Deleted user ${req.params.username}`,
      };
    }, userBack),
  );

  admin.get(
    "/pools/:poolId/groups",
    page(async (req, res) => {
      const ctx = ctxOf(req);
      const pool = await services.cognito.getUserPool(ctx, req.params.poolId);
      send(
        res,
        "Groups",
        "pools",
        groupsPage({
          pool: pool.options,
          groups: await pool.listGroups(ctx),
          users: (await pool.listUsers(ctx)).length,
        }),
        flashOf(req),
      );
    }),
  );

  admin.post(
    "/pools/:poolId/groups",
    action(
      async (req) => {
        const name = str(req.body?.name);
        if (!name) throw new Error("Group name is required");
        const precedence = str(req.body?.precedence);
        await run(req, "CreateGroup", {
          UserPoolId: req.params.poolId,
          GroupName: name,
          Description: str(req.body?.description) || undefined,
          Precedence: precedence ? Number(precedence) : undefined,
        });
        return `Created group ${name}`;
      },
      (req) => adminUrl("pools", req.params.poolId, "groups"),
    ),
  );

  admin.get(
    "/codes",
    page(async (req, res) => {
      const ctx = ctxOf(req);
      const filters = codeFilters(req);
      const entries = filterCodes(
        await enrichEntries(ctx, services.codeLog?.list() ?? []),
        filters,
      );
      send(
        res,
        "Codes",
        "codes",
        codesPage({
          entries,
          sessions: sessionsFor(filters),
          pools: await services.cognito.listUserPools(ctx),
          filters,
          enabled: !!services.codeLog,
          capacity: services.config.AdminUIConfig?.CodeLogSize,
        }),
        flashOf(req),
      );
    }),
  );

  admin.get("/api/codes", async (req, res) => {
    const filters = codeFilters(req);
    const limit = Number(str(req.query.limit)) || undefined;
    const entries = filterCodes(
      await enrichEntries(ctxOf(req), services.codeLog?.list() ?? []),
      filters,
    ).slice(0, limit);
    res.set("Cache-Control", "no-store").json({
      codes: entries,
      sessions: sessionsFor(filters).map((s) => ({
        session: s.id.slice(0, 8),
        userPoolId: s.session.userPoolId,
        clientId: s.session.clientId,
        username: s.session.username,
        challengeName: s.session.pendingChallenge.challengeName,
        privateChallengeParameters:
          s.session.pendingChallenge.privateChallengeParameters,
        expiresAt: s.expiresAt,
      })),
    });
  });

  const tokens = async (req: Request, res: Response) => {
    const ctx = ctxOf(req);
    const pools = await services.cognito.listUserPools(ctx);
    const token = str(req.body?.token);
    const poolId = str(req.body?.pool);
    if (!token) {
      send(res, "Tokens", "tokens", tokensPage({ pools, token, poolId }));
      return;
    }

    let resolvedPoolId = poolId || undefined;
    if (!resolvedPoolId) {
      try {
        const payload = JSON.parse(
          Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"),
        );
        const fromIss = String(payload?.iss ?? "")
          .split("/")
          .pop();
        resolvedPoolId = pools.find((p) => p.Id === fromIss)?.Id;
      } catch {
        resolvedPoolId = undefined;
      }
    }

    const issuerDomain = services.config.TokenConfig?.IssuerDomain;
    const result = inspectToken(token, {
      jwks: [PublicKey.jwk],
      expectedIssuer:
        resolvedPoolId && issuerDomain
          ? `${issuerDomain}/${resolvedPoolId}`
          : undefined,
      clientIds: resolvedPoolId
        ? (await services.cognito.listAppClients(ctx, resolvedPoolId)).map(
            (c) => c.ClientId,
          )
        : undefined,
      now: services.clock.get(),
    });
    send(
      res,
      "Tokens",
      "tokens",
      tokensPage({ pools, token, poolId, resolvedPoolId, result }),
    );
  };
  admin.get("/tokens", page(tokens));
  admin.post("/tokens", page(tokens));

  admin.use("/callback", createCallbackRouter(services));

  admin.get("/api/status", async (req, res) => {
    const ctx = ctxOf(req);
    const pools = await services.cognito.listUserPools(ctx);
    res.set("Cache-Control", "no-store").json({
      running: true,
      pools: pools.length,
      issuerDomain: services.config.TokenConfig?.IssuerDomain,
    });
  });

  admin.get("/api/export", async (req, res) => {
    const seed = await exportSeed(ctxOf(req), services);
    if (str(req.query.download)) {
      res.attachment("cognito-local.seed.json");
    }
    res
      .set("Cache-Control", "no-store")
      .type("json")
      .send(`${JSON.stringify(seed, null, 2)}\n`);
  });

  admin.post("/api/seed", express.json({ limit: "20mb" }), async (req, res) => {
    const source = str(req.query.source) || "request body";
    try {
      const body: unknown = req.body;
      assertValidSeed(body, source);
      const seed = resolveSeedFileTargets(
        body,
        str(req.query.baseDir) || process.cwd(),
        source,
      );
      const result = await applySeed(ctxOf(req), services, seed, source);
      res.json({
        ...result,
        summary: summarizeSeedResult(result),
        lines: formatSeedResult(result),
      });
    } catch (e) {
      if (e instanceof SeedValidationError) {
        res.status(400).json({ error: e.message, issues: e.issues });
        return;
      }
      if (e instanceof SeedApplyError) {
        res.status(400).json({ error: e.message, path: e.path });
        return;
      }
      res.status(500).json({ error: (e as Error)?.message ?? String(e) });
    }
  });

  return admin;
};
