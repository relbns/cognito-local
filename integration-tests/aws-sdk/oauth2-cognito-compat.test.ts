import { createHash } from "node:crypto";
import * as jwt from "jsonwebtoken";
import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "./setup";

const CALLBACK = "http://localhost:9999/cb";

const basicAuth = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;

function backendAuthorizeUrl(
  serverUrl: string,
  clientId: string,
  extra = "",
): string {
  return (
    `${serverUrl}/oauth2/authorize?` +
    `redirect_uri=${CALLBACK}&response_type=CODE&client_id=${clientId}` +
    `&scope=openid+email+profile+phone&state=s1${extra}`
  );
}

function formFields(html: string): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const m of html.matchAll(/name="([^"]+)" value="([^"]*)"/g)) {
    fields[m[1]] = m[2].replace(/&amp;/g, "&");
  }
  return fields;
}

describe(
  "OAuth2 requests shaped like real Cognito clients send them",
  withCognitoSdk((Cognito, { serverUrl }) => {
    async function setup() {
      const client = Cognito();
      const pool = await client.createUserPool({ PoolName: "test" }).promise();
      const userPoolId = pool.UserPool!.Id!;
      const upc = await client
        .createUserPoolClient({
          UserPoolId: userPoolId,
          ClientName: "idp",
          GenerateSecret: true,
          AllowedOAuthFlowsUserPoolClient: true,
          AllowedOAuthFlows: ["code", "implicit"],
          AllowedOAuthScopes: ["email", "openid", "phone", "profile"],
          CallbackURLs: [CALLBACK],
          LogoutURLs: ["http://localhost:9999/out"],
          SupportedIdentityProviders: ["COGNITO", "examplesaml"],
        })
        .promise();
      await client
        .createIdentityProvider({
          UserPoolId: userPoolId,
          ProviderName: "examplesaml",
          ProviderType: "OIDC",
          ProviderDetails: {
            client_id: "x",
            client_secret: "y",
            oidc_issuer: "https://idp.example.test",
            authorize_scopes: "openid email",
          },
        })
        .promise();
      await client
        .adminCreateUser({
          UserPoolId: userPoolId,
          Username: "testuser",
          TemporaryPassword: "Temp1234!",
          UserAttributes: [{ Name: "email", Value: "test@example.com" }],
          MessageAction: "SUPPRESS",
        })
        .promise();
      await client
        .adminSetUserPassword({
          UserPoolId: userPoolId,
          Username: "testuser",
          Password: "Password1!",
          Permanent: true,
        })
        .promise();
      return {
        clientId: upc.UserPoolClient!.ClientId!,
        clientSecret: upc.UserPoolClient!.ClientSecret!,
      };
    }

    async function login(authorizeUrl: string): Promise<URL> {
      const formRes = await fetch(authorizeUrl, { redirect: "manual" });
      expect(formRes.status).toBe(200);
      const fields = formFields(await formRes.text());
      const loginRes = await fetch(`${serverUrl()}/oauth2/authorize`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          ...fields,
          username: "testuser",
          password: "Password1!",
        }).toString(),
        redirect: "manual",
      });
      expect(loginRes.status).toBe(302);
      return new URL(loginRes.headers.get("location")!);
    }

    function exchange(
      body: Record<string, string>,
      authorization?: string,
    ): Promise<Response> {
      return fetch(`${serverUrl()}/oauth2/token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          ...(authorization ? { Authorization: authorization } : {}),
        },
        body: new URLSearchParams(body).toString(),
      });
    }

    it("completes the backend's code flow: upper-case CODE, no PKCE, Basic secret", async () => {
      const { clientId, clientSecret } = await setup();
      const redirect = await login(backendAuthorizeUrl(serverUrl(), clientId));
      expect(redirect.searchParams.get("state")).toBe("s1");
      const code = redirect.searchParams.get("code")!;

      const res = await exchange(
        {
          grant_type: "authorization_code",
          client_id: clientId,
          redirect_uri: CALLBACK,
          code,
        },
        basicAuth(clientId, clientSecret),
      );
      expect(res.status).toBe(200);
      const tokens = await res.json();
      expect(tokens.id_token).toBeTruthy();
      expect(tokens.refresh_token).toBeTruthy();
      expect((jwt.decode(tokens.access_token) as jwt.JwtPayload).scope).toBe(
        "openid email profile phone",
      );

      const refreshed = await exchange(
        {
          grant_type: "refresh_token",
          client_id: clientId,
          refresh_token: tokens.refresh_token,
        },
        basicAuth(clientId, clientSecret),
      );
      expect(refreshed.status).toBe(200);
      const refreshedTokens = await refreshed.json();
      expect(
        (jwt.decode(refreshedTokens.access_token) as jwt.JwtPayload).scope,
      ).toBe("openid email profile phone");
    });

    it("rejects a wrong or missing client secret with invalid_client", async () => {
      const { clientId } = await setup();
      const redirect = await login(backendAuthorizeUrl(serverUrl(), clientId));
      const body = {
        grant_type: "authorization_code",
        client_id: clientId,
        redirect_uri: CALLBACK,
        code: redirect.searchParams.get("code")!,
      };
      const wrong = await exchange(body, basicAuth(clientId, "wrong"));
      expect(wrong.status).toBe(400);
      expect((await wrong.json()).error).toBe("invalid_client");
      const missing = await exchange(body);
      expect((await missing.json()).error).toBe("invalid_client");
    });

    it("enforces PKCE at the token endpoint when a code_challenge was sent", async () => {
      const { clientId, clientSecret } = await setup();
      const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
      const challenge = createHash("sha256")
        .update(verifier)
        .digest("base64url");
      const pkce = `&code_challenge=${challenge}&code_challenge_method=S256`;
      const body = (code: string) => ({
        grant_type: "authorization_code",
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: CALLBACK,
        code,
      });

      const first = await login(
        backendAuthorizeUrl(serverUrl(), clientId, pkce),
      );
      const noVerifier = await exchange(body(first.searchParams.get("code")!));
      expect((await noVerifier.json()).error).toBe("invalid_grant");

      const second = await login(
        backendAuthorizeUrl(serverUrl(), clientId, pkce),
      );
      const ok = await exchange({
        ...body(second.searchParams.get("code")!),
        code_verifier: verifier,
      });
      expect(ok.status).toBe(200);
    });

    it("redirects invalid_scope for a scope the client does not allow", async () => {
      const { clientId } = await setup();
      const res = await fetch(
        `${serverUrl()}/oauth2/authorize?redirect_uri=${CALLBACK}&response_type=code&client_id=${clientId}&scope=openid+admin&state=s1`,
        { redirect: "manual" },
      );
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get("location")!);
      expect(location.origin + location.pathname).toBe(CALLBACK);
      expect(location.searchParams.get("error")).toBe("invalid_scope");
      expect(location.searchParams.get("state")).toBe("s1");
    });

    it("shows the login for identity_provider=COGNITO and the mock IdP for a federated IdP", async () => {
      const { clientId } = await setup();
      const cognito = await fetch(
        backendAuthorizeUrl(
          serverUrl(),
          clientId,
          "&identity_provider=COGNITO",
        ),
        { redirect: "manual" },
      );
      expect(cognito.status).toBe(200);

      const federated = await fetch(
        backendAuthorizeUrl(
          serverUrl(),
          clientId,
          "&identity_provider=examplesaml",
        ),
        { redirect: "manual" },
      );
      expect(federated.status).toBe(302);
      expect(federated.headers.get("location")).toMatch(
        /^\/mock-idp\/examplesaml\/authorize\?/,
      );
    });

    it("returns implicit-grant tokens in the URL fragment", async () => {
      const { clientId } = await setup();
      const redirect = await login(
        `${serverUrl()}/oauth2/authorize?redirect_uri=${CALLBACK}&response_type=token&client_id=${clientId}&scope=openid+email&state=s1`,
      );
      const fragment = new URLSearchParams(redirect.hash.slice(1));
      expect(fragment.get("access_token")).toBeTruthy();
      expect(fragment.get("id_token")).toBeTruthy();
      expect(fragment.get("state")).toBe("s1");
    });
  }),
);
