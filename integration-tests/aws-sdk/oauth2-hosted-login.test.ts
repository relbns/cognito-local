import type { CognitoIdentityServiceProvider } from "aws-sdk";
import { describe, expect, it } from "vitest";
import { generate } from "../../src/services/totp";
import { withCognitoSdk } from "./setup";

const CALLBACK = "http://localhost:9876/cb";
const TEMP_PASSWORD = "TempPassw0rd!";
const PASSWORD = "Passw0rd!";

const postForm = (serverUrl: string, body: Record<string, string>) =>
  fetch(`${serverUrl}/oauth2/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
    redirect: "manual",
  });

const sessionOf = (html: string): string => {
  const match = html.match(/name="login_session" value="([^"]+)"/);
  if (!match) throw new Error(`no login_session in ${html}`);
  return match[1];
};

const setupPool = async (
  client: CognitoIdentityServiceProvider,
  mfa: "OFF" | "OPTIONAL" = "OFF",
) => {
  const pool = await client
    .createUserPool({ PoolName: "hosted", MfaConfiguration: mfa })
    .promise();
  const userPoolId = pool.UserPool?.Id as string;
  if (mfa !== "OFF") {
    await client
      .setUserPoolMfaConfig({
        UserPoolId: userPoolId,
        MfaConfiguration: mfa,
        SoftwareTokenMfaConfiguration: { Enabled: true },
      })
      .promise();
  }
  const upc = await client
    .createUserPoolClient({
      UserPoolId: userPoolId,
      ClientName: "web",
      AllowedOAuthFlows: ["code"],
      AllowedOAuthScopes: ["openid", "email"],
      CallbackURLs: [CALLBACK],
      ExplicitAuthFlows: ["ALLOW_USER_PASSWORD_AUTH"],
    })
    .promise();
  return { userPoolId, clientId: upc.UserPoolClient?.ClientId as string };
};

const createUser = async (
  client: CognitoIdentityServiceProvider,
  userPoolId: string,
  username: string,
  { permanent = true, phone }: { permanent?: boolean; phone?: string } = {},
) => {
  await client
    .adminCreateUser({
      UserPoolId: userPoolId,
      Username: username,
      TemporaryPassword: TEMP_PASSWORD,
      UserAttributes: [
        { Name: "email", Value: `${username}@example.test` },
        ...(phone ? [{ Name: "phone_number", Value: phone }] : []),
      ],
      MessageAction: "SUPPRESS",
    })
    .promise();
  if (permanent) {
    await client
      .adminSetUserPassword({
        UserPoolId: userPoolId,
        Username: username,
        Password: PASSWORD,
        Permanent: true,
      })
      .promise();
  }
};

const expectCode = async (
  res: Response,
  serverUrl: string,
  clientId: string,
) => {
  expect(res.status).toBe(302);
  const location = new URL(res.headers.get("location") as string);
  expect(location.searchParams.get("state")).toBe("st");
  const tokenRes = await fetch(`${serverUrl}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      redirect_uri: CALLBACK,
      code: location.searchParams.get("code") as string,
    }).toString(),
  });
  expect(tokenRes.status).toBe(200);
  return tokenRes.json();
};

describe(
  "Hosted login form",
  withCognitoSdk((Cognito, { serverUrl, messageDelivery }) => {
    const login = (clientId: string, username: string, password: string) =>
      postForm(serverUrl(), {
        client_id: clientId,
        redirect_uri: CALLBACK,
        response_type: "code",
        scope: "openid email",
        state: "st",
        username,
        password,
      });

    it("refuses a disabled user", async () => {
      const client = Cognito();
      const { userPoolId, clientId } = await setupPool(client);
      await createUser(client, userPoolId, "disabled");
      await client
        .adminDisableUser({ UserPoolId: userPoolId, Username: "disabled" })
        .promise();

      const res = await login(clientId, "disabled", PASSWORD);
      expect(res.status).toBe(200);
      expect(await res.text()).toContain("User is disabled.");
    });

    it("sets a new password for a user with a temporary one", async () => {
      const client = Cognito();
      const { userPoolId, clientId } = await setupPool(client);
      await createUser(client, userPoolId, "jane", { permanent: false });

      const first = await login(clientId, "jane", TEMP_PASSWORD);
      const session = sessionOf(await first.text());

      const weak = await postForm(serverUrl(), {
        login_session: session,
        new_password: "weak",
        confirm_password: "weak",
      });
      expect(await weak.text()).toContain(
        "Password does not conform to policy",
      );

      const done = await postForm(serverUrl(), {
        login_session: session,
        new_password: PASSWORD,
        confirm_password: PASSWORD,
      });
      const tokens = await expectCode(done, serverUrl(), clientId);
      expect(tokens.access_token).toBeTruthy();

      const user = await client
        .adminGetUser({ UserPoolId: userPoolId, Username: "jane" })
        .promise();
      expect(user.UserStatus).toBe("CONFIRMED");
      const again = await login(clientId, "jane", PASSWORD);
      expect(again.status).toBe(302);
    });

    it("asks for an SMS code and records it in the codes viewer", async () => {
      const client = Cognito();
      const { userPoolId, clientId } = await setupPool(client, "OPTIONAL");
      await createUser(client, userPoolId, "sms", { phone: "+15555550100" });
      await client
        .adminSetUserMFAPreference({
          UserPoolId: userPoolId,
          Username: "sms",
          SMSMfaSettings: { Enabled: true, PreferredMfa: true },
        })
        .promise();

      const first = await login(clientId, "sms", PASSWORD);
      const session = sessionOf(await first.text());
      const sent = messageDelivery().collectedMessages.at(-1);
      expect(sent?.deliveryDetails).toEqual({
        DeliveryMedium: "SMS",
        AttributeName: "phone_number",
        Destination: "+15555550100",
      });
      const code = sent?.message.__code as string;

      const viewer = await (
        await fetch(`${serverUrl()}/_admin/api/codes?pool=${userPoolId}`)
      ).json();
      expect(viewer.codes[0]).toMatchObject({ type: "MFA", code });

      const wrong = await postForm(serverUrl(), {
        login_session: session,
        code: code === "000000" ? "111111" : "000000",
      });
      expect(await wrong.text()).toContain(
        "Invalid code or auth state for the user.",
      );

      await expectCode(
        await postForm(serverUrl(), { login_session: session, code }),
        serverUrl(),
        clientId,
      );
    });

    it("asks for a TOTP code from the user's authenticator", async () => {
      const client = Cognito();
      const { userPoolId, clientId } = await setupPool(client, "OPTIONAL");
      await createUser(client, userPoolId, "totp");
      const auth = await client
        .initiateAuth({
          ClientId: clientId,
          AuthFlow: "USER_PASSWORD_AUTH",
          AuthParameters: { USERNAME: "totp", PASSWORD },
        })
        .promise();
      const accessToken = auth.AuthenticationResult?.AccessToken as string;
      const { SecretCode } = await client
        .associateSoftwareToken({ AccessToken: accessToken })
        .promise();
      const secret = SecretCode as string;
      await client
        .verifySoftwareToken({
          AccessToken: accessToken,
          UserCode: generate(secret),
        })
        .promise();
      await client
        .setUserMFAPreference({
          AccessToken: accessToken,
          SoftwareTokenMfaSettings: { Enabled: true, PreferredMfa: true },
        })
        .promise();

      const first = await login(clientId, "totp", PASSWORD);
      const html = await first.text();
      expect(html).toContain("authenticator app");

      await expectCode(
        await postForm(serverUrl(), {
          login_session: sessionOf(html),
          code: generate(secret),
        }),
        serverUrl(),
        clientId,
      );
    });
  }),
);
