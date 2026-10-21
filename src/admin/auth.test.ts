import bodyParser from "body-parser";
import express from "express";
import type supertest from "supertest";
import { describe, expect, it } from "vitest";
import { localRequest } from "../__tests__/localRequest";
import { ADMIN_TOKEN_COOKIE, adminAuth, adminTokenWarning } from "./auth";
import { ADMIN_UI_PATH } from "./html";

const request = localRequest();

const TOKEN = "s3cret-admin-token";

const appWith = (token: string | undefined) => {
  const app = express();
  const admin = express.Router();
  admin.use(bodyParser.urlencoded({ extended: false }));
  admin.use(adminAuth(token));
  admin.get("/", (_req, res) => {
    res.send("pools page");
  });
  admin.get("/pools/:id", (req, res) => {
    res.send(`pool ${req.params.id} ${JSON.stringify(req.query)}`);
  });
  admin.get("/api/status", (_req, res) => {
    res.json({ running: true });
  });
  admin.post("/pools", (_req, res) => {
    res.send("created");
  });
  app.use(ADMIN_UI_PATH, admin);
  return app;
};

const cookieOf = (response: supertest.Response) =>
  ([] as string[])
    .concat(response.header["set-cookie"] ?? [])
    .map((c) => c.split(";")[0])
    .join("; ");

describe("adminAuth", () => {
  it("leaves every route open without a token", async () => {
    const app = appWith(undefined);

    expect((await request(app).get("/_admin/api/status")).status).toBe(200);
    expect((await request(app).get("/_admin")).text).toBe("pools page");
  });

  it("requires the token as a Bearer header on the API", async () => {
    const app = appWith(TOKEN);

    const missing = await request(app).get("/_admin/api/status");
    expect(missing.status).toBe(401);
    expect(missing.header["www-authenticate"]).toBe(
      'Bearer realm="cognito-local admin"',
    );
    expect(missing.body.error).toContain("Authorization: Bearer");

    const wrong = await request(app)
      .get("/_admin/api/status")
      .set("Authorization", "Bearer nope");
    expect(wrong.status).toBe(401);

    const right = await request(app)
      .get("/_admin/api/status")
      .set("Authorization", `Bearer ${TOKEN}`);
    expect(right.status).toBe(200);
    expect(right.body).toEqual({ running: true });
  });

  it("does not accept the token in the query string of an API call", async () => {
    const response = await request(appWith(TOKEN)).get(
      `/_admin/api/status?token=${TOKEN}`,
    );

    expect(response.status).toBe(401);
  });

  it("sends a browser to the sign-in page and back after a correct token", async () => {
    const app = appWith(TOKEN);

    const page = await request(app).get("/_admin/pools/p1?tab=users");
    expect(page.status).toBe(303);
    expect(page.header.location).toBe(
      "/_admin/login?next=%2F_admin%2Fpools%2Fp1%3Ftab%3Dusers",
    );

    const form = await request(app).get(page.header.location);
    expect(form.status).toBe(200);
    expect(form.text).toContain('name="token"');
    expect(form.text).toContain('value="/_admin/pools/p1?tab=users"');

    const wrong = await request(app)
      .post("/_admin/login")
      .type("form")
      .send({ token: "nope", next: "/_admin/pools/p1" });
    expect(wrong.status).toBe(401);
    expect(wrong.text).toContain("That token is not correct.");
    expect(wrong.header["set-cookie"]).toBeUndefined();

    const login = await request(app)
      .post("/_admin/login")
      .type("form")
      .send({ token: TOKEN, next: "/_admin/pools/p1?tab=users" });
    expect(login.status).toBe(303);
    expect(login.header.location).toBe("/_admin/pools/p1?tab=users");
    const setCookie = String(login.header["set-cookie"]);
    expect(setCookie).toContain(`${ADMIN_TOKEN_COOKIE}=`);
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Lax");
    expect(setCookie).toContain("Path=/_admin");
    expect(setCookie).not.toContain(TOKEN);

    const after = await request(app)
      .get("/_admin/pools/p1?tab=users")
      .set("Cookie", cookieOf(login));
    expect(after.status).toBe(200);
    expect(after.text).toBe('pool p1 {"tab":"users"}');

    const api = await request(app)
      .get("/_admin/api/status")
      .set("Cookie", cookieOf(login));
    expect(api.status).toBe(200);
  });

  it("never redirects outside the admin UI after sign-in", async () => {
    const login = await request(appWith(TOKEN))
      .post("/_admin/login")
      .type("form")
      .send({ token: TOKEN, next: "https://example.com/" });

    expect(login.header.location).toBe("/_admin");
  });

  it("turns ?token= into the cookie and drops it from the URL", async () => {
    const app = appWith(TOKEN);

    const bootstrap = await request(app).get(
      `/_admin/pools/p1?token=${TOKEN}&tab=users`,
    );
    expect(bootstrap.status).toBe(303);
    expect(bootstrap.header.location).toBe("/_admin/pools/p1?tab=users");

    const after = await request(app)
      .get("/_admin/pools/p1?tab=users")
      .set("Cookie", cookieOf(bootstrap));
    expect(after.status).toBe(200);

    const wrong = await request(app).get("/_admin/pools/p1?token=nope");
    expect(wrong.status).toBe(401);
    expect(wrong.text).toContain("That token is not correct.");
  });

  it("refuses a form post without the cookie", async () => {
    const response = await request(appWith(TOKEN))
      .post("/_admin/pools")
      .type("form")
      .send({ name: "x" });

    expect(response.status).toBe(401);
  });

  it("clears the cookie on sign-out", async () => {
    const response = await request(appWith(TOKEN)).post("/_admin/logout");

    expect(response.status).toBe(303);
    expect(response.header.location).toBe("/_admin/login");
    expect(String(response.header["set-cookie"])).toContain("Max-Age=0");
  });
});

describe("adminTokenWarning", () => {
  it.each(["localhost", "127.0.0.1", "127.0.0.2", "::1"])(
    "stays quiet on the loopback host %s",
    (hostname) => {
      expect(
        adminTokenWarning({ hostname, adminUi: true, token: undefined }),
      ).toBeUndefined();
    },
  );

  it.each(["0.0.0.0", "::", "cognito", undefined])(
    "warns about an open admin UI on %s",
    (hostname) => {
      expect(
        adminTokenWarning({ hostname, adminUi: true, token: undefined }),
      ).toContain("COGNITO_LOCAL_ADMIN_TOKEN");
    },
  );

  it("stays quiet with a token or without the admin UI", () => {
    expect(
      adminTokenWarning({ hostname: "0.0.0.0", adminUi: true, token: TOKEN }),
    ).toBeUndefined();
    expect(
      adminTokenWarning({
        hostname: "0.0.0.0",
        adminUi: false,
        token: undefined,
      }),
    ).toBeUndefined();
  });
});
