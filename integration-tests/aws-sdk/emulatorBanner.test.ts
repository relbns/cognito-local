import { beforeEach, describe, expect, it } from "vitest";
import { DefaultConfig } from "../../src/server/config";
import { PRODUCT_TAGLINE } from "../../src/server/emulatorBanner";
import { withCognitoSdk } from "./setup";

const CALLBACK = "http://localhost:9876/cb";

const expectBanner = (html: string) => {
  expect(html).toContain("data-emulator-banner");
  expect(html).toContain(">cognito-emulator</a>");
  expect(html).toContain(PRODUCT_TAGLINE);
  expect(html).toContain('<a href="/_admin">Admin UI</a>');
  expect(html).toContain('<a href="/_admin/codes">Codes</a>');
  expect(html.match(/<header\b/g)).toHaveLength(1);
  expect(html.indexOf("data-emulator-banner")).toBeLessThan(
    html.indexOf("<main"),
  );
};

const adminConfig = (
  overrides: Partial<typeof DefaultConfig.AdminUIConfig>,
) => ({
  ...DefaultConfig,
  AdminUIConfig: {
    ...DefaultConfig.AdminUIConfig,
    Enabled: true,
    Token: undefined,
    ...overrides,
  },
});

describe(
  "emulator banner on every browser page",
  withCognitoSdk(
    (Cognito, { serverUrl }) => {
      let clientId: string;
      let query: string;

      beforeEach(async () => {
        const pool = await Cognito()
          .createUserPool({ PoolName: "banner" })
          .promise();
        const userPoolId = pool.UserPool!.Id!;
        await Cognito()
          .createIdentityProvider({
            UserPoolId: userPoolId,
            ProviderName: "Google",
            ProviderType: "Google",
            ProviderDetails: {
              client_id: "google-client",
              client_secret: "google-secret",
              authorize_scopes: "openid email",
            },
            AttributeMapping: { email: "email", username: "sub" },
          })
          .promise();
        const client = await Cognito()
          .createUserPoolClient({
            UserPoolId: userPoolId,
            ClientName: "banner-web",
            AllowedOAuthFlowsUserPoolClient: true,
            AllowedOAuthFlows: ["code"],
            AllowedOAuthScopes: ["openid", "email"],
            CallbackURLs: [CALLBACK],
            SupportedIdentityProviders: ["COGNITO", "Google"],
          })
          .promise();
        clientId = client.UserPoolClient!.ClientId!;
        query = new URLSearchParams({
          client_id: clientId,
          redirect_uri: CALLBACK,
          response_type: "code",
          scope: "openid email",
          state: "st",
        }).toString();
      });

      const get = async (path: string) => {
        const res = await fetch(`${serverUrl()}${path}`, {
          redirect: "manual",
        });
        return {
          status: res.status,
          type: res.headers.get("content-type"),
          location: res.headers.get("location"),
          html: await res.text(),
        };
      };

      const post = async (path: string, fields: Record<string, string>) => {
        const res = await fetch(`${serverUrl()}${path}`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams(fields).toString(),
          redirect: "manual",
        });
        return { status: res.status, html: await res.text() };
      };

      it.each([
        "/login",
        "/oauth2/authorize",
        "/signup",
        "/forgotPassword",
        "/confirm?username=banner-user",
        "/confirmForgotPassword?username=banner-user",
        "/passkeys/add",
      ])("hosted page %s", async (path) => {
        const page = await get(
          `${path}${path.includes("?") ? "&" : "?"}${query}`,
        );
        expect(page.type).toMatch(/^text\/html/);
        expectBanner(page.html);
      });

      it("hosted login error and the sign-up outcome", async () => {
        const fields = Object.fromEntries(new URLSearchParams(query));
        const failed = await post("/oauth2/authorize", {
          ...fields,
          username: "nobody",
          password: "wrong",
        });
        expect(failed.status).toBe(200);
        expectBanner(failed.html);

        const signedUp = await post("/signup", {
          ...fields,
          username: "banner-user",
          password: "Passw0rd!",
        });
        expect(signedUp.html).toContain("Your account was created");
        expectBanner(signedUp.html);
      });

      it("mock IdP page and its error pages", async () => {
        const authorize = await get(
          `/oauth2/authorize?${query}&identity_provider=Google`,
        );
        expect(authorize.status).toBe(302);
        const res = await fetch(new URL(authorize.location!, serverUrl()));
        const mockIdp = await res.text();
        expectBanner(mockIdp);
        expect(mockIdp).toContain("banner-web");
        expect(mockIdp).toContain(`<code>${CALLBACK}</code>`);

        const unknown = await get("/mock-idp/Google/authorize?state=unknown");
        expect(unknown.status).toBe(400);
        expectBanner(unknown.html);

        const expired = await post("/oauth2/idpresponse", { state: "unknown" });
        expect(expired.status).toBe(400);
        expectBanner(expired.html);
      });

      it.each([
        "/_admin",
        "/_admin/codes",
        "/_admin/tokens",
        "/_admin/callback",
        "/_admin/pools/missing",
      ])("admin page %s", async (path) => {
        expectBanner((await get(path)).html);
      });
    },
    { config: adminConfig({}) },
  ),
);

describe(
  "emulator banner on the admin sign-in page",
  withCognitoSdk(
    (_Cognito, { serverUrl }) => {
      it("shows the banner before the token is given", async () => {
        const res = await fetch(`${serverUrl()}/_admin/codes`);
        const html = await res.text();
        expect(html).toContain("Admin token required");
        expectBanner(html);
      });
    },
    { config: adminConfig({ Token: "banner-token" }) },
  ),
);

describe(
  "emulator banner when the admin UI is off",
  withCognitoSdk(
    (_Cognito, { serverUrl }) => {
      it.each(["/_admin", "/_admin/codes"])(
        "answers %s with a branded 404",
        async (path) => {
          const res = await fetch(`${serverUrl()}${path}`);
          expect(res.status).toBe(404);
          const html = await res.text();
          expect(html).toContain("Admin UI is turned off");
          expectBanner(html);
        },
      );
    },
    { config: adminConfig({ Enabled: false }) },
  ),
);
