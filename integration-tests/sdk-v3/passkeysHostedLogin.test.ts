import {
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  CognitoIdentityProviderClient,
  CreateUserPoolClientCommand,
  CreateUserPoolCommand,
  ListWebAuthnCredentialsCommand,
  SetUserPoolMfaConfigCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { describe, expect, it } from "vitest";
import {
  SoftwareAuthenticator,
  type SoftwareCredential,
} from "../../src/__tests__/softwareAuthenticator";
import { withCognitoSdk } from "../aws-sdk/setup";

const CALLBACK = "http://localhost:9876/cb";
const PASSWORD = "Example-Passw0rd!";
const USERNAME = "hosted-passkey-user";
const ORIGIN = "http://localhost:9229";
const credentials = { accessKeyId: "local", secretAccessKey: "local" };

const optionsOf = (html: string) => {
  const match = html.match(
    /<script type="application\/json" id="passkey-options">(.*?)<\/script>/s,
  );
  if (!match) throw new Error(`no passkey options in ${html}`);
  return JSON.parse(match[1]);
};

const sessionOf = (html: string): string => {
  const match = html.match(/name="login_session" value="([^"]+)"/);
  if (!match) throw new Error(`no login_session in ${html}`);
  return match[1];
};

describe(
  "hosted passkey pages",
  withCognitoSdk((_, { serverUrl }) => {
    const form = (
      path: string,
      body: Record<string, string>,
      cookie?: string,
    ) =>
      fetch(`${serverUrl()}${path}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          ...(cookie ? { Cookie: cookie } : {}),
        },
        body: new URLSearchParams(body).toString(),
        redirect: "manual",
      });

    const setUp = async (
      allowedFactors = ["PASSWORD", "WEB_AUTHN"] as const,
    ) => {
      const cognito = new CognitoIdentityProviderClient({
        endpoint: serverUrl(),
        region: "local",
        credentials,
        maxAttempts: 1,
      });
      const pool = await cognito.send(
        new CreateUserPoolCommand({
          PoolName: "hosted-passkeys",
          Policies: {
            SignInPolicy: { AllowedFirstAuthFactors: [...allowedFactors] },
          },
        }),
      );
      const userPoolId = pool.UserPool?.Id as string;
      await cognito.send(
        new SetUserPoolMfaConfigCommand({
          UserPoolId: userPoolId,
          WebAuthnConfiguration: { RelyingPartyId: "localhost" },
        }),
      );
      const client = await cognito.send(
        new CreateUserPoolClientCommand({
          UserPoolId: userPoolId,
          ClientName: "web",
          AllowedOAuthFlows: ["code"],
          AllowedOAuthFlowsUserPoolClient: true,
          AllowedOAuthScopes: ["openid", "aws.cognito.signin.user.admin"],
          CallbackURLs: [CALLBACK],
          ExplicitAuthFlows: ["ALLOW_USER_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        }),
      );
      await cognito.send(
        new AdminCreateUserCommand({
          UserPoolId: userPoolId,
          Username: USERNAME,
          MessageAction: "SUPPRESS",
        }),
      );
      await cognito.send(
        new AdminSetUserPasswordCommand({
          UserPoolId: userPoolId,
          Username: USERNAME,
          Password: PASSWORD,
          Permanent: true,
        }),
      );
      const clientId = client.UserPoolClient?.ClientId as string;
      const authorize = {
        client_id: clientId,
        redirect_uri: CALLBACK,
        response_type: "code",
        scope: "openid aws.cognito.signin.user.admin",
        state: "st",
      };
      const tokensFor = async (res: Response) => {
        expect(res.status).toBe(302);
        const location = new URL(res.headers.get("location") as string);
        const token = await form("/oauth2/token", {
          grant_type: "authorization_code",
          client_id: clientId,
          redirect_uri: CALLBACK,
          code: location.searchParams.get("code") as string,
        });
        expect(token.status).toBe(200);
        return (await token.json()) as { access_token: string };
      };
      return { cognito, clientId, authorize, tokensFor };
    };

    const registerThroughPage = async (
      env: Awaited<ReturnType<typeof setUp>>,
      authenticator: SoftwareAuthenticator,
    ): Promise<{ credential: SoftwareCredential; accessToken: string }> => {
      const login = await form("/oauth2/authorize", {
        ...env.authorize,
        username: USERNAME,
        password: PASSWORD,
      });
      const cookie = (login.headers.get("set-cookie") as string).split(";")[0];
      const { access_token } = await env.tokensFor(login);

      const page = await fetch(
        `${serverUrl()}/passkeys/add?client_id=${env.clientId}&redirect_uri=${encodeURIComponent(CALLBACK)}`,
        { headers: { Cookie: cookie } },
      );
      expect(page.status).toBe(200);
      const html = await page.text();
      expect(html).toContain("Add passkey");
      const options = optionsOf(html);
      expect(options.rp.id).toEqual("localhost");

      const created = authenticator.create({
        rpId: options.rp.id,
        origin: ORIGIN,
        challenge: options.challenge,
        userHandle: options.user.id,
      });
      const added = await form(
        "/passkeys/add",
        {
          client_id: env.clientId,
          redirect_uri: CALLBACK,
          credential: JSON.stringify(created.response),
        },
        cookie,
      );
      expect(added.status).toBe(302);
      expect(added.headers.get("location")).toEqual(CALLBACK);
      return { credential: created.credential, accessToken: access_token };
    };

    it("offers passkey sign-in on the login page only when the pool allows it", async () => {
      const on = await setUp();
      const page = await fetch(
        `${serverUrl()}/login?${new URLSearchParams(on.authorize)}`,
      );
      expect(await page.text()).toContain("Sign in with passkey");

      const off = await setUp(["PASSWORD"] as never);
      const plain = await fetch(
        `${serverUrl()}/login?${new URLSearchParams(off.authorize)}`,
      );
      expect(await plain.text()).not.toContain("Sign in with passkey");
    });

    it("registers a passkey on /passkeys/add and signs in with it", async () => {
      const env = await setUp();
      const authenticator = new SoftwareAuthenticator();
      const { credential, accessToken } = await registerThroughPage(
        env,
        authenticator,
      );
      const listed = await env.cognito.send(
        new ListWebAuthnCredentialsCommand({ AccessToken: accessToken }),
      );
      expect(listed.Credentials?.map((c) => c.CredentialId)).toEqual([
        credential.id.toString("base64url"),
      ]);

      const start = await form("/oauth2/authorize", {
        ...env.authorize,
        username: USERNAME,
        passkey: "true",
      });
      expect(start.status).toBe(200);
      const html = await start.text();
      const session = sessionOf(html);
      const options = optionsOf(html);
      expect(options.allowCredentials).toEqual([
        { id: credential.id.toString("base64url"), type: "public-key" },
      ]);
      const assertion = (badSignature = false) =>
        JSON.stringify(
          authenticator.get(credential, {
            rpId: "localhost",
            origin: ORIGIN,
            challenge: options.challenge,
            badSignature,
          }),
        );

      const refused = await form("/oauth2/authorize", {
        login_session: session,
        credential: assertion(true),
      });
      expect(refused.status).toBe(200);
      expect(await refused.text()).toContain(
        "The passkey could not be verified. Try again.",
      );

      const signedIn = await form("/oauth2/authorize", {
        login_session: session,
        credential: assertion(),
      });
      const tokens = await env.tokensFor(signedIn);
      expect(tokens.access_token).toBeTruthy();
    });

    it("refuses passkey sign-in for a user without a passkey", async () => {
      const env = await setUp();
      for (const username of [USERNAME, "nobody"]) {
        const res = await form("/oauth2/authorize", {
          ...env.authorize,
          username,
          passkey: "true",
        });
        expect(await res.text()).toContain(
          "Passkey sign-in is not available for this user.",
        );
      }
    });

    it("asks for a signed-in browser and a registered redirect_uri on /passkeys/add", async () => {
      const env = await setUp();
      const anonymous = await fetch(
        `${serverUrl()}/passkeys/add?client_id=${env.clientId}&redirect_uri=${encodeURIComponent(CALLBACK)}`,
      );
      expect(anonymous.status).toBe(401);
      expect(await anonymous.text()).toContain(
        "Sign in before adding a passkey.",
      );

      const wrong = await fetch(
        `${serverUrl()}/passkeys/add?client_id=${env.clientId}&redirect_uri=${encodeURIComponent("http://example.test/cb")}`,
      );
      expect(wrong.status).toBe(400);
    });
  }),
);
