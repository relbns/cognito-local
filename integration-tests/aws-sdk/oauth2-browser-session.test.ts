import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "./setup";

const CALLBACK = "http://localhost:9876/cb";
const LOGOUT = "http://localhost:9876/signed-out";

const cookieOf = (res: Response): string | undefined =>
  res.headers
    .getSetCookie()
    .find((c) => c.startsWith("cognito="))
    ?.split(";")[0];

describe(
  "hosted login browser session",
  withCognitoSdk((Cognito, { serverUrl }) => {
    const setup = async () => {
      const client = Cognito();
      const pool = await client
        .createUserPool({ PoolName: "session", UsernameAttributes: [] })
        .promise();
      const UserPoolId = pool.UserPool!.Id!;
      await client
        .createIdentityProvider({
          UserPoolId,
          ProviderName: "ExampleOIDC",
          ProviderType: "OIDC",
          ProviderDetails: {
            client_id: "example",
            client_secret: "example-secret",
            oidc_issuer: "https://login.example.test",
            authorize_scopes: "openid email",
          },
          AttributeMapping: { email: "email", username: "sub" },
        })
        .promise();
      const app = await client
        .createUserPoolClient({
          UserPoolId,
          ClientName: "web",
          AllowedOAuthFlowsUserPoolClient: true,
          AllowedOAuthFlows: ["code"],
          AllowedOAuthScopes: ["openid", "email"],
          CallbackURLs: [CALLBACK],
          LogoutURLs: [LOGOUT],
          SupportedIdentityProviders: ["COGNITO", "ExampleOIDC"],
        })
        .promise();
      await client
        .adminCreateUser({
          UserPoolId,
          Username: "jane",
          MessageAction: "SUPPRESS",
        })
        .promise();
      await client
        .adminSetUserPassword({
          UserPoolId,
          Username: "jane",
          Password: "Passw0rd!",
          Permanent: true,
        })
        .promise();
      return { ClientId: app.UserPoolClient!.ClientId! };
    };

    const authorize = (
      ClientId: string,
      cookie?: string,
      extra: Record<string, string> = {},
    ) =>
      fetch(
        `${serverUrl()}/oauth2/authorize?${new URLSearchParams({
          client_id: ClientId,
          redirect_uri: CALLBACK,
          response_type: "code",
          scope: "openid email",
          state: "s1",
          ...extra,
        })}`,
        { redirect: "manual", headers: cookie ? { Cookie: cookie } : {} },
      );

    const signIn = async (ClientId: string) => {
      const res = await fetch(`${serverUrl()}/oauth2/authorize`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: ClientId,
          redirect_uri: CALLBACK,
          response_type: "code",
          scope: "openid email",
          state: "s1",
          username: "jane",
          password: "Passw0rd!",
        }).toString(),
        redirect: "manual",
      });
      expect(res.status).toBe(302);
      return cookieOf(res) as string;
    };

    const exchange = async (ClientId: string, location: string) => {
      const code = new URL(location).searchParams.get("code") as string;
      const res = await fetch(`${serverUrl()}/oauth2/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: ClientId,
          code,
          redirect_uri: CALLBACK,
        }).toString(),
      });
      return res.status;
    };

    it("signs in again from the session cookie until /logout", async () => {
      const { ClientId } = await setup();
      const cookie = await signIn(ClientId);
      expect(cookie).toMatch(/^cognito=/);

      const silent = await authorize(ClientId, cookie, { prompt: "none" });
      expect(silent.status).toBe(302);
      const location = silent.headers.get("location") as string;
      expect(new URL(location).searchParams.get("state")).toBe("s1");
      expect(await exchange(ClientId, location)).toBe(200);

      const again = await authorize(ClientId, cookie);
      expect(again.status).toBe(302);
      expect(
        new URL(again.headers.get("location")!).searchParams.has("code"),
      ).toBe(true);

      const forced = await authorize(ClientId, cookie, { prompt: "login" });
      expect(forced.status).toBe(200);

      const out = await fetch(
        `${serverUrl()}/logout?${new URLSearchParams({ client_id: ClientId, logout_uri: LOGOUT })}`,
        { redirect: "manual", headers: { Cookie: cookie } },
      );
      expect(out.status).toBe(302);
      expect(out.headers.get("location")).toBe(LOGOUT);
      expect(cookieOf(out)).toBe("cognito=");

      const after = await authorize(ClientId, cookie, { prompt: "none" });
      expect(
        Object.fromEntries(
          new URL(after.headers.get("location")!).searchParams,
        ),
      ).toEqual({
        error: "login_required",
        state: "s1",
      });
    });

    it("starts a session from a federated sign-in", async () => {
      const { ClientId } = await setup();
      const start = await authorize(ClientId, undefined, {
        identity_provider: "ExampleOIDC",
      });
      const idp = new URL(start.headers.get("location")!, serverUrl());
      const res = await fetch(`${serverUrl()}/oauth2/idpresponse`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          state: idp.searchParams.get("state") as string,
          subject: "fed-user-1",
          claim_name: "email",
          claim_value: "fed@example.test",
        }).toString(),
        redirect: "manual",
      });
      expect(res.status).toBe(302);
      const cookie = cookieOf(res);
      expect(cookie).toMatch(/^cognito=.+/);

      const silent = await authorize(ClientId, cookie, { prompt: "none" });
      expect(
        new URL(silent.headers.get("location")!).searchParams.has("code"),
      ).toBe(true);
    });
  }),
);
