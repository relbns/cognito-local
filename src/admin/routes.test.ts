import express from "express";
import * as jwt from "jsonwebtoken";
import type { MockedObject } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { localRequest } from "../__tests__/localRequest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidPasswordError, ResourceNotFoundError } from "../errors";
import PrivateKey from "../keys/cognitoLocal.private.json";
import { DefaultConfig } from "../server/config";
import type { CognitoService, UserPoolService } from "../services";
import { InMemoryAuthSessions } from "../services/authSessions";
import { InMemoryCodeLog, RecordingAuthSessions } from "../services/codeLog";
import { ADMIN_UI_PATH } from "./html";
import { createAdminRouter } from "./routes";

const request = localRequest();

const XSS = `<script>alert("x")</script>`;
const ESCAPED = "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;";

describe("admin UI routes", () => {
  let pool: MockedObject<UserPoolService>;
  let cognito: MockedObject<CognitoService>;
  let route: ReturnType<typeof vi.fn>;
  let router: ReturnType<typeof vi.fn>;
  let clock: ClockFake;
  let codeLog: InMemoryCodeLog;
  let authSessions: RecordingAuthSessions;
  let app: express.Express;
  let user: ReturnType<typeof TDB.user>;

  beforeEach(() => {
    user = TDB.user({
      Username: "jane",
      UserStatus: "UNCONFIRMED",
      ConfirmationCode: "424242",
      Attributes: [
        { Name: "email", Value: "jane@example.com" },
        { Name: "phone_number", Value: "+15555550100" },
        { Name: "sub", Value: "sub-1" },
      ],
    });
    const other = TDB.user({
      Username: "bob",
      Attributes: [{ Name: "email", Value: "bob@example.com" }],
    });
    pool = newMockUserPoolService(
      TDB.userPool({ Id: "local_pool", Name: "Local pool" }),
    );
    pool.listUsers.mockResolvedValue([user, other]);
    pool.listGroups.mockResolvedValue([
      TDB.group({ GroupName: "admins", members: ["bob"] }),
      TDB.group({ GroupName: "editors" }),
    ]);
    pool.getUserByUsername.mockImplementation(async (_ctx, username) =>
      username === "jane" ? user : username === "bob" ? other : null,
    );
    pool.listUserGroupMembership.mockResolvedValue(["admins"]);

    cognito = newMockCognitoService(pool);
    cognito.listUserPools.mockResolvedValue([pool.options]);
    cognito.listAppClients.mockResolvedValue([
      TDB.appClient({
        ClientId: "client-1",
        ClientName: "web",
        UserPoolId: "local_pool",
        AllowedOAuthFlows: ["code"],
        AllowedOAuthScopes: ["openid", "email"],
        CallbackURLs: ["http://localhost:3000/cb"],
        ClientSecret: "s3cret",
      }),
    ]);

    route = vi.fn().mockResolvedValue({ User: { Username: "new-user" } });
    router = vi.fn().mockReturnValue(route);
    clock = new ClockFake(new Date("2026-01-01T00:00:00Z"));
    codeLog = new InMemoryCodeLog(clock);
    authSessions = new RecordingAuthSessions(
      new InMemoryAuthSessions(clock),
      codeLog,
    );

    app = express();
    app.use((req, _res, next) => {
      (req as any).log = {
        child: () => (req as any).log,
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {},
      };
      next();
    });
    app.use(
      ADMIN_UI_PATH,
      createAdminRouter(
        {
          authSessions,
          clock,
          codeLog,
          cognito,
          config: DefaultConfig,
        } as any,
        router as any,
      ),
    );
  });

  const get = (path: string) => request(app).get(`${ADMIN_UI_PATH}${path}`);
  const post = (path: string, form: Record<string, string> = {}) =>
    request(app).post(`${ADMIN_UI_PATH}${path}`).type("form").send(form);

  describe("pages", () => {
    it("lists user pools with their counts and the no-auth notice", async () => {
      const res = await get("/").expect(200).expect("Content-Type", /html/);
      expect(res.text).toContain("Local pool");
      expect(res.text).toContain(`href="/_admin/pools/local_pool"`);
      expect(res.text).toContain("No authentication: local development only");
    });

    it("asks for the admin token and then shows a sign-out button instead of the notice", async () => {
      const protectedApp = express();
      protectedApp.use((req, _res, next) => {
        (req as any).log = { debug() {}, info() {}, warn() {}, error() {} };
        next();
      });
      protectedApp.use(
        ADMIN_UI_PATH,
        createAdminRouter(
          {
            authSessions,
            clock,
            codeLog,
            cognito,
            config: {
              ...DefaultConfig,
              AdminUIConfig: { ...DefaultConfig.AdminUIConfig, Token: "t0ken" },
            },
          } as any,
          router as any,
        ),
      );

      await request(protectedApp)
        .get(ADMIN_UI_PATH)
        .expect(303)
        .expect("Location", "/_admin/login?next=%2F_admin");
      const res = await request(protectedApp)
        .get(ADMIN_UI_PATH)
        .set("Authorization", "Bearer t0ken")
        .expect(200);
      expect(res.text).toContain("Local pool");
      expect(res.text).toContain(`action="/_admin/logout"`);
      expect(res.text).not.toContain("No authentication");
    });

    it("shows pool settings and app clients with their OAuth settings", async () => {
      const res = await get("/pools/local_pool").expect(200);
      expect(res.text).toContain("client-1");
      expect(res.text).toContain("http://localhost:3000/cb");
      expect(res.text).toContain("openid");
      expect(res.text).toContain("s3cret");
    });

    it("returns 404 for an unknown pool", async () => {
      cognito.getUserPool.mockRejectedValue(
        new ResourceNotFoundError("User Pool nope not found"),
      );
      const res = await get("/pools/nope").expect(404);
      expect(res.text).toContain("User Pool nope not found");
    });

    it("filters users by username, email or phone", async () => {
      const byEmail = await get("/pools/local_pool/users?q=BOB@").expect(200);
      expect(byEmail.text).toContain("/users/bob");
      expect(byEmail.text).not.toContain("/users/jane");

      const byPhone = await get("/pools/local_pool/users?q=5550100").expect(
        200,
      );
      expect(byPhone.text).toContain("/users/jane");
      expect(byPhone.text).not.toContain("/users/bob");

      const byStatus = await get(
        "/pools/local_pool/users?status=UNCONFIRMED",
      ).expect(200);
      expect(byStatus.text).toContain("1 of 2 users");
    });

    it("shows a user's attributes, groups, pending codes and actions", async () => {
      const res = await get("/pools/local_pool/users/jane").expect(200);
      expect(res.text).toContain("jane@example.com");
      expect(res.text).toContain("424242");
      expect(res.text).toContain("/users/jane/groups/remove");
      expect(res.text).toContain(`<option value="editors">`);
      expect(res.text).toContain("/users/jane/confirm");
    });

    it("lists groups with their members", async () => {
      const res = await get("/pools/local_pool/groups").expect(200);
      expect(res.text).toContain("admins");
      expect(res.text).toContain("/users/bob");
    });

    it("escapes user-controlled data everywhere it is rendered", async () => {
      user.Attributes.push({ Name: "custom:bio", Value: XSS });
      pool.listGroups.mockResolvedValue([
        TDB.group({ GroupName: XSS, Description: XSS, members: ["jane"] }),
      ]);
      codeLog.record({
        type: "SIGN_UP",
        source: "SignUp",
        userPoolId: "local_pool",
        username: XSS,
        code: XSS,
      });

      for (const path of [
        "/pools/local_pool/users/jane",
        "/pools/local_pool/groups",
        "/pools/local_pool/users",
        `/codes?q=${encodeURIComponent("<script")}`,
        `/?ok=${encodeURIComponent(XSS)}`,
      ]) {
        const res = await get(path).expect(200);
        expect(res.text, path).not.toContain(XSS);
        expect(res.text, path).toContain(ESCAPED);
      }
    });
  });

  describe("user actions", () => {
    it("creates a user through AdminCreateUser and makes the password permanent", async () => {
      const res = await post("/pools/local_pool/users", {
        username: "new-user",
        email: "new@example.com",
        password: "Passw0rd!",
        permanent: "1",
        verified: "1",
        attributes: "custom:tier=gold",
      }).expect(303);

      expect(router).toHaveBeenNthCalledWith(1, "AdminCreateUser");
      expect(route).toHaveBeenNthCalledWith(1, expect.anything(), {
        UserPoolId: "local_pool",
        Username: "new-user",
        UserAttributes: [
          { Name: "email", Value: "new@example.com" },
          { Name: "email_verified", Value: "true" },
          { Name: "custom:tier", Value: "gold" },
        ],
        TemporaryPassword: "Passw0rd!",
        MessageAction: "SUPPRESS",
        DesiredDeliveryMediums: undefined,
      });
      expect(router).toHaveBeenNthCalledWith(2, "AdminSetUserPassword");
      expect(route).toHaveBeenNthCalledWith(2, expect.anything(), {
        UserPoolId: "local_pool",
        Username: "new-user",
        Password: "Passw0rd!",
        Permanent: true,
      });
      expect(res.header.location).toEqual(
        "/_admin/pools/local_pool/users/new-user?ok=Created+user+new-user",
      );
    });

    it.each([
      ["confirm", "AdminConfirmSignUp", {}],
      ["enable", "AdminEnableUser", {}],
      ["disable", "AdminDisableUser", {}],
      [
        "password",
        "AdminSetUserPassword",
        { Password: "N3wPass!", Permanent: true },
        { password: "N3wPass!", permanent: "1" },
      ],
      [
        "groups/add",
        "AdminAddUserToGroup",
        { GroupName: "editors" },
        { group: "editors" },
      ],
      [
        "groups/remove",
        "AdminRemoveUserFromGroup",
        { GroupName: "admins" },
        { group: "admins" },
      ],
    ] as [string, string, object, Record<string, string>?][])(
      "%s calls %s and redirects back with a message",
      async (path, target, extra, form = {}) => {
        const res = await post(
          `/pools/local_pool/users/jane/${path}`,
          form,
        ).expect(303);

        expect(router).toHaveBeenCalledWith(target);
        expect(route).toHaveBeenCalledWith(expect.anything(), {
          UserPoolId: "local_pool",
          Username: "jane",
          ...extra,
        });
        expect(res.header.location).toMatch(
          /^\/_admin\/pools\/local_pool\/users\/jane\?ok=/,
        );
      },
    );

    it("deletes a user and returns to the user list", async () => {
      const res = await post("/pools/local_pool/users/jane/delete").expect(303);
      expect(router).toHaveBeenCalledWith("AdminDeleteUser");
      expect(res.header.location).toEqual(
        "/_admin/pools/local_pool/users?ok=Deleted+user+jane",
      );
    });

    it("creates a group through CreateGroup", async () => {
      await post("/pools/local_pool/groups", {
        name: "ops",
        precedence: "3",
      }).expect(303);
      expect(router).toHaveBeenCalledWith("CreateGroup");
      expect(route).toHaveBeenCalledWith(expect.anything(), {
        UserPoolId: "local_pool",
        GroupName: "ops",
        Description: undefined,
        Precedence: 3,
      });
    });

    it("shows the target's error as a flash message", async () => {
      route.mockRejectedValue(new InvalidPasswordError());
      const res = await post("/pools/local_pool/users/jane/password", {
        password: "x",
      }).expect(303);
      const location = new URL(res.header.location, "http://x");
      expect(location.searchParams.get("error")).toMatch(
        /^InvalidPasswordException/,
      );

      const page = await request(app).get(res.header.location);
      expect(page.text).toContain(`class="flash error"`);
    });

    it("refuses cross-site form posts", async () => {
      await request(app)
        .post(`${ADMIN_UI_PATH}/pools/local_pool/users/jane/delete`)
        .set("Origin", "http://evil.example")
        .expect(403);
      await request(app)
        .post(`${ADMIN_UI_PATH}/pools/local_pool/users/jane/delete`)
        .set("Sec-Fetch-Site", "cross-site")
        .expect(403);
      expect(router).not.toHaveBeenCalled();
    });
  });

  describe("codes feed", () => {
    beforeEach(() => {
      codeLog.record({
        type: "SIGN_UP",
        source: "SignUp",
        userPoolId: "local_pool",
        username: "jane",
        code: "111111",
        deliveryMedium: "EMAIL",
        destination: "jane@example.com",
      });
      clock.advanceBy(1000);
      authSessions.create({
        userPoolId: "local_pool",
        clientId: "client-1",
        username: "bob",
        history: [],
        pendingChallenge: {
          challengeName: "CUSTOM_CHALLENGE",
          privateChallengeParameters: { secretLoginCode: "987654" },
        },
      });
    });

    it("renders codes newest first and the active CUSTOM_AUTH sessions", async () => {
      const res = await get("/codes").expect(200);
      expect(res.text.indexOf("987654")).toBeLessThan(
        res.text.indexOf("111111"),
      );
      expect(res.text).toContain("Active CUSTOM_AUTH sessions (1)");
      expect(res.text).toContain(`data-expires="2026-01-01T00:03:01.000Z"`);
    });

    it("returns the feed as JSON, enriched and filterable", async () => {
      const all = await get("/api/codes").expect(200);
      expect(all.body.codes.map((c: any) => c.code)).toEqual([
        "987654",
        "111111",
      ]);
      expect(all.body.codes[0]).toMatchObject({
        type: "CUSTOM_AUTH",
        username: "bob",
        email: "bob@example.com",
        round: 1,
      });
      expect(all.body.sessions).toEqual([
        expect.objectContaining({
          username: "bob",
          privateChallengeParameters: { secretLoginCode: "987654" },
          expiresAt: "2026-01-01T00:03:01.000Z",
        }),
      ]);

      const byEmail = await get("/api/codes?q=jane@").expect(200);
      expect(byEmail.body.codes.map((c: any) => c.code)).toEqual(["111111"]);
      expect(byEmail.body.sessions).toEqual([]);

      const byType = await get("/api/codes?type=CUSTOM_AUTH&limit=1");
      expect(byType.body.codes.map((c: any) => c.code)).toEqual(["987654"]);
    });

    it("hides expired sessions but keeps their codes", async () => {
      clock.advanceBy(3 * 60_000);
      const res = await get("/api/codes").expect(200);
      expect(res.body.sessions).toEqual([]);
      expect(res.body.codes).toHaveLength(2);
    });
  });

  describe("tokens", () => {
    const token = (iss: string) =>
      jwt.sign(
        {
          token_use: "access",
          client_id: "client-1",
          sub: "sub-1",
          exp: Math.floor(clock.get().getTime() / 1000) + 60,
        },
        PrivateKey.pem,
        { algorithm: "RS256", keyid: "CognitoLocal", issuer: iss },
      );

    it("renders the empty form", async () => {
      const res = await get("/tokens").expect(200);
      expect(res.text).toContain(`<textarea name="token"`);
    });

    it("decodes a token and verifies it against the pool from the iss claim", async () => {
      const res = await post("/tokens", {
        token: token(`${DefaultConfig.TokenConfig.IssuerDomain}/local_pool`),
      }).expect(200);
      expect(res.text).toContain("against <code>local_pool</code>");
      expect(res.text).toContain("&quot;sub&quot;: &quot;sub-1&quot;");
      expect(res.text).not.toContain(`class="check-fail"`);
    });

    it("flags a token issued for another pool", async () => {
      const res = await post("/tokens", {
        token: token("http://elsewhere/other_pool"),
        pool: "local_pool",
      }).expect(200);
      expect(res.text).toContain(`class="check-fail"`);
    });
  });
});
