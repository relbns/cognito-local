import type { CognitoIdentityServiceProvider } from "aws-sdk";
import { beforeEach, describe, expect, it } from "vitest";
import { fakeLambdaClient } from "../../src/__tests__/fakeLambdaClient";
import { type Lambda, LambdaService } from "../../src/services";
import { generate } from "../../src/services/totp";
import { withCognitoSdk } from "./setup";

const CALLBACK = "http://localhost:9876/cb";
const PASSWORD = "Passw0rd!";
const NEW_PASSWORD = "NewPassw0rd!";

const OAUTH = {
  redirect_uri: CALLBACK,
  response_type: "code",
  scope: "openid email",
  state: "st",
};

const sessionOf = (html: string): string => {
  const match = html.match(/name="login_session" value="([^"]+)"/);
  if (!match) throw new Error(`no login_session in ${html}`);
  return match[1];
};

const cookieOf = (res: Response): string | undefined =>
  res.headers
    .getSetCookie()
    .find((c) => c.startsWith("cognito="))
    ?.split(";")[0];

type TriggerEvent = {
  triggerSource: string;
  userName: string;
  request: Record<string, any>;
  response: Record<string, any>;
};

let handlers: Record<string, (event: TriggerEvent) => unknown> = {};
let invocations: { name: string; event: TriggerEvent }[] = [];

const lambdaService = new LambdaService(
  Object.fromEntries(
    [
      "CustomMessage",
      "PostAuthentication",
      "PostConfirmation",
      "PreAuthentication",
      "PreSignUp",
      "UserMigration",
    ].map((name) => [name, name]),
  ),
  fakeLambdaClient(async (name, event: TriggerEvent) => {
    invocations.push({ name, event: structuredClone(event) });
    await handlers[name]?.(event);
    return event;
  }),
);

const lambda = (): Lambda => ({
  enabled: (name) => name in handlers,
  invoke: lambdaService.invoke.bind(lambdaService) as Lambda["invoke"],
});

const sourcesOf = (name: string) =>
  invocations.filter((x) => x.name === name).map((x) => x.event.triggerSource);

const setupPool = async (
  client: CognitoIdentityServiceProvider,
  {
    usernameAttributes = ["email"],
    adminOnly = false,
    mfa = "OFF",
    secret = false,
    required = ["name"],
  }: {
    usernameAttributes?: string[];
    adminOnly?: boolean;
    mfa?: "OFF" | "ON";
    secret?: boolean;
    required?: string[];
  } = {},
) => {
  const pool = await client
    .createUserPool({
      PoolName: "pages",
      UsernameAttributes: usernameAttributes,
      AutoVerifiedAttributes: ["email"],
      MfaConfiguration: mfa,
      AdminCreateUserConfig: { AllowAdminCreateUserOnly: adminOnly },
      ...(required.length
        ? {
            Schema: required.map((Name) => ({
              Name,
              AttributeDataType: "String",
              Required: true,
              Mutable: true,
            })),
          }
        : {}),
      Policies: {
        PasswordPolicy: {
          MinimumLength: 8,
          RequireUppercase: true,
          RequireLowercase: true,
          RequireNumbers: true,
          RequireSymbols: false,
        },
      },
    })
    .promise();
  const userPoolId = pool.UserPool?.Id as string;
  if (mfa === "ON") {
    await client
      .setUserPoolMfaConfig({
        UserPoolId: userPoolId,
        MfaConfiguration: "ON",
        SoftwareTokenMfaConfiguration: { Enabled: true },
      })
      .promise();
  }
  const upc = await client
    .createUserPoolClient({
      UserPoolId: userPoolId,
      ClientName: "web",
      GenerateSecret: secret,
      AllowedOAuthFlowsUserPoolClient: true,
      AllowedOAuthFlows: ["code"],
      AllowedOAuthScopes: ["openid", "email"],
      CallbackURLs: [CALLBACK],
    })
    .promise();
  return {
    userPoolId,
    clientId: upc.UserPoolClient?.ClientId as string,
    clientSecret: upc.UserPoolClient?.ClientSecret,
  };
};

const pages = (serverUrl: () => string) => {
  const get = (path: string, query: Record<string, string>) =>
    fetch(`${serverUrl()}${path}?${new URLSearchParams(query)}`, {
      redirect: "manual",
    });
  const post = (path: string, body: Record<string, string>) =>
    fetch(`${serverUrl()}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString(),
      redirect: "manual",
    });
  const exchange = async (
    res: Response,
    clientId: string,
    clientSecret?: string,
  ) => {
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("location") as string);
    expect(`${location.origin}${location.pathname}`).toBe(CALLBACK);
    expect(location.searchParams.get("state")).toBe("st");
    const tokenRes = await fetch(`${serverUrl()}/oauth2/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...(clientSecret
          ? {
              Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`,
            }
          : {}),
      },
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
  return { get, post, exchange };
};

describe(
  "Hosted UI pages",
  withCognitoSdk((Cognito, { serverUrl, codeLog }) => {
    const { get, post, exchange } = pages(serverUrl);
    const lastCode = (type: string) =>
      codeLog()
        .list()
        .find((entry) => entry.type === type)?.code as string;

    describe("login page links", () => {
      it("links sign-up and forgot password with the authorize parameters", async () => {
        const { clientId } = await setupPool(Cognito());
        const html = await (
          await get("/oauth2/authorize", { client_id: clientId, ...OAUTH })
        ).text();
        const query = new URLSearchParams({
          client_id: clientId,
          response_type: "code",
          scope: "openid email",
          redirect_uri: CALLBACK,
          state: "st",
        })
          .toString()
          .replace(/&/g, "&amp;");
        expect(html).toContain(`href="/signup?${query}"`);
        expect(html).toContain(`href="/forgotPassword?${query}"`);
        expect(html).toContain('autocomplete="current-password"');
      });

      it("hides sign-up and refuses the page when only administrators create users", async () => {
        const { clientId } = await setupPool(Cognito(), { adminOnly: true });
        const login = await (
          await get("/oauth2/authorize", { client_id: clientId, ...OAUTH })
        ).text();
        expect(login).not.toContain("/signup?");
        expect(login).toContain("/forgotPassword?");

        const page = await get("/signup", { client_id: clientId, ...OAUTH });
        expect(page.status).toBe(400);
        expect(await page.text()).toContain(
          "SignUp is not permitted for this user pool",
        );
        const submit = await post("/signup", {
          client_id: clientId,
          ...OAUTH,
          username: "new@example.test",
          password: PASSWORD,
        });
        expect(submit.status).toBe(400);
      });

      it("checks the authorize parameters like the login form", async () => {
        const { clientId } = await setupPool(Cognito());
        const res = await get("/signup", {
          client_id: clientId,
          ...OAUTH,
          redirect_uri: "http://elsewhere.example.test/cb",
        });
        expect(res.status).toBe(400);
        expect((await res.json()).error_description).toContain(
          "redirect_mismatch",
        );
      });
    });

    describe("sign-in of an unconfirmed user", () => {
      it("sends a code, shows the confirm page and signs in after the code", async () => {
        const client = Cognito();
        const { clientId } = await setupPool(client, { required: [] });
        await client
          .signUp({
            ClientId: clientId,
            Username: "late@example.test",
            Password: PASSWORD,
          })
          .promise();
        const wrong = await post("/oauth2/authorize", {
          client_id: clientId,
          ...OAUTH,
          username: "late@example.test",
          password: "Wrong-Passw0rd",
        });
        expect(await wrong.text()).toContain("Incorrect username or password.");

        const confirmPage = await (
          await post("/oauth2/authorize", {
            client_id: clientId,
            ...OAUTH,
            username: "late@example.test",
            password: PASSWORD,
          })
        ).text();
        expect(confirmPage).toContain(
          "We have sent a code by email to l***@e***",
        );
        const code = lastCode("SIGN_UP");
        expect(code).toMatch(/^\d{6}$/);
        expect(
          codeLog()
            .list()
            .filter((e) => e.type === "SIGN_UP"),
        ).toHaveLength(2);

        const confirmed = await post("/confirm", {
          login_session: sessionOf(confirmPage),
          code,
        });
        await exchange(confirmed, clientId);
      });
    });

    describe("sign-up", () => {
      it("signs up, confirms with the delivered code and lands on the redirect with a code", async () => {
        const client = Cognito();
        const { userPoolId, clientId } = await setupPool(client);

        const form = await (
          await get("/signup", { client_id: clientId, ...OAUTH })
        ).text();
        expect(form).toContain(
          '<input type="email" name="username" autocomplete="email" required />',
        );
        expect(form).toContain('name="requiredAttributes[name]"');
        expect(form).toContain('autocomplete="new-password"');

        const signUp = (password: string) =>
          post("/signup", {
            client_id: clientId,
            ...OAUTH,
            username: "jane@example.test",
            "requiredAttributes[name]": "Jane Example",
            password,
          });

        const weak = await (await signUp("weak")).text();
        expect(weak).toContain("Password did not conform with policy");
        expect(weak).toContain('value="jane@example.test"');
        expect(weak).not.toContain('value="weak"');

        const confirmPage = await (await signUp(PASSWORD)).text();
        expect(confirmPage).toContain(
          "We have sent a code by email to j***@e***",
        );
        const first = lastCode("SIGN_UP");
        expect(first).toMatch(/^\d{6}$/);
        let session = sessionOf(confirmPage);

        const wrong = await post("/confirm", {
          login_session: session,
          code: first === "000000" ? "111111" : "000000",
        });
        expect(await wrong.text()).toContain(
          "Invalid verification code provided, please try again.",
        );

        const resent = await (
          await post("/resendcode", { login_session: session })
        ).text();
        expect(resent).toContain("We have sent a new code.");
        const second = lastCode("SIGN_UP");
        expect(
          codeLog()
            .list()
            .filter((e) => e.type === "SIGN_UP"),
        ).toHaveLength(2);
        expect(
          (await post("/confirm", { login_session: session, code: second }))
            .status,
        ).toBe(400);
        session = sessionOf(resent);

        const confirmed = await post("/confirm", {
          login_session: session,
          code: second,
        });
        expect(cookieOf(confirmed)).toBeTruthy();
        const tokens = await exchange(confirmed, clientId);
        expect(tokens.id_token).toBeTruthy();

        const user = await client
          .adminGetUser({
            UserPoolId: userPoolId,
            Username: "jane@example.test",
          })
          .promise();
        expect(user.UserStatus).toBe("CONFIRMED");
        expect(user.UserAttributes).toEqual(
          expect.arrayContaining([
            { Name: "email_verified", Value: "true" },
            { Name: "name", Value: "Jane Example" },
          ]),
        );
      });

      it("shows SignUp's errors on the form", async () => {
        const client = Cognito();
        const { clientId } = await setupPool(client);
        const signUp = (fields: Record<string, string>) =>
          post("/signup", {
            client_id: clientId,
            ...OAUTH,
            password: PASSWORD,
            ...fields,
          });

        expect(
          await (await signUp({ username: "missing@example.test" })).text(),
        ).toContain("name: The attribute is required");

        await signUp({
          username: "taken@example.test",
          "requiredAttributes[name]": "Taken",
        });
        expect(
          await (
            await signUp({
              username: "taken@example.test",
              "requiredAttributes[name]": "Taken",
            })
          ).text(),
        ).toContain("An account with the given email already exists.");
      });

      it("uses a username field and the client secret for a pool without username attributes", async () => {
        const client = Cognito();
        const { userPoolId, clientId, clientSecret } = await setupPool(client, {
          usernameAttributes: [],
          required: ["email"],
          secret: true,
        });
        const form = await (
          await get("/signup", { client_id: clientId, ...OAUTH })
        ).text();
        expect(form).toContain(
          '<label>Username: <input type="text" name="username" autocomplete="username" required />',
        );
        expect(form).toContain(
          '<input type="email" name="requiredAttributes[email]" autocomplete="email" required />',
        );

        const page = await post("/signup", {
          client_id: clientId,
          ...OAUTH,
          username: "jdoe",
          "requiredAttributes[email]": "jdoe@example.test",
          password: PASSWORD,
        });
        const session = sessionOf(await page.text());
        const done = await post("/confirm", {
          login_session: session,
          code: lastCode("SIGN_UP"),
        });
        await exchange(done, clientId, clientSecret);
        const user = await client
          .adminGetUser({ UserPoolId: userPoolId, Username: "jdoe" })
          .promise();
        expect(user.UserStatus).toBe("CONFIRMED");
      });

      it("confirms from a confirm link without signing in", async () => {
        const client = Cognito();
        const { userPoolId, clientId } = await setupPool(client, {
          required: [],
        });
        await client
          .signUp({
            ClientId: clientId,
            Username: "link@example.test",
            Password: PASSWORD,
          })
          .promise();

        const page = await (
          await get("/confirm", {
            client_id: clientId,
            ...OAUTH,
            username: "link@example.test",
          })
        ).text();
        const res = await post("/confirm", {
          login_session: sessionOf(page),
          code: lastCode("SIGN_UP"),
        });
        expect(res.status).toBe(200);
        expect(cookieOf(res)).toBeUndefined();
        const html = await res.text();
        expect(html).toContain(
          "Your account is confirmed. Sign in to continue.",
        );
        expect(html).toContain('name="password"');
        const user = await client
          .adminGetUser({
            UserPoolId: userPoolId,
            Username: "link@example.test",
          })
          .promise();
        expect(user.UserStatus).toBe("CONFIRMED");
      });

      it("refuses a session from another page or one never issued", async () => {
        const client = Cognito();
        const { userPoolId, clientId } = await setupPool(client, {
          required: [],
        });
        await client
          .adminCreateUser({
            UserPoolId: userPoolId,
            Username: "reset@example.test",
            UserAttributes: [
              { Name: "email", Value: "reset@example.test" },
              { Name: "email_verified", Value: "true" },
            ],
            MessageAction: "SUPPRESS",
          })
          .promise();
        await client
          .adminSetUserPassword({
            UserPoolId: userPoolId,
            Username: "reset@example.test",
            Password: "Example-Passw0rd!",
            Permanent: true,
          })
          .promise();
        const forgot = await (
          await post("/forgotPassword", {
            client_id: clientId,
            ...OAUTH,
            username: "reset@example.test",
          })
        ).text();

        expect(
          (
            await post("/confirm", {
              login_session: sessionOf(forgot),
              code: "1",
            })
          ).status,
        ).toBe(400);
        expect(
          (await post("/confirm", { login_session: "forged", code: "1" }))
            .status,
        ).toBe(400);
        expect(
          (
            await post("/oauth2/authorize", {
              login_session: sessionOf(forgot),
              code: "1",
            })
          ).status,
        ).toBe(400);
      });
    });

    describe("forgot password", () => {
      const createUser = async (
        client: CognitoIdentityServiceProvider,
        userPoolId: string,
      ) => {
        await client
          .adminCreateUser({
            UserPoolId: userPoolId,
            Username: "sam@example.test",
            UserAttributes: [
              { Name: "email", Value: "sam@example.test" },
              { Name: "email_verified", Value: "true" },
              { Name: "name", Value: "Sam" },
            ],
            MessageAction: "SUPPRESS",
          })
          .promise();
        await client
          .adminSetUserPassword({
            UserPoolId: userPoolId,
            Username: "sam@example.test",
            Password: PASSWORD,
            Permanent: true,
          })
          .promise();
      };

      it("resets the password with the delivered code, then signs in with it", async () => {
        const client = Cognito();
        const { userPoolId, clientId } = await setupPool(client);
        await createUser(client, userPoolId);

        const form = await (
          await get("/forgotPassword", { client_id: clientId, ...OAUTH })
        ).text();
        expect(form).toContain('<form method="POST" action="/forgotPassword">');
        expect(form).toContain('name="username" autocomplete="username"');

        const confirmPage = await (
          await post("/forgotPassword", {
            client_id: clientId,
            ...OAUTH,
            username: "sam@example.test",
          })
        ).text();
        expect(confirmPage).toContain(
          "We have sent a password reset code by email to s***@e***",
        );
        const session = sessionOf(confirmPage);
        const code = lastCode("FORGOT_PASSWORD");
        const confirm = (fields: Record<string, string>) =>
          post("/confirmForgotPassword", { login_session: session, ...fields });

        expect(
          await (
            await confirm({
              code,
              new_password: NEW_PASSWORD,
              confirm_password: "different",
            })
          ).text(),
        ).toContain("Passwords do not match.");
        expect(
          await (
            await confirm({
              code,
              new_password: "weak",
              confirm_password: "weak",
            })
          ).text(),
        ).toContain("Password does not conform to policy");
        expect(
          await (
            await confirm({
              code: code === "000000" ? "111111" : "000000",
              new_password: NEW_PASSWORD,
              confirm_password: NEW_PASSWORD,
            })
          ).text(),
        ).toContain("Invalid verification code provided, please try again.");

        const done = await confirm({
          code,
          new_password: NEW_PASSWORD,
          confirm_password: NEW_PASSWORD,
        });
        expect(await done.text()).toContain(
          "Your password has been reset. Sign in with your new password.",
        );

        const signIn = await post("/oauth2/authorize", {
          client_id: clientId,
          ...OAUTH,
          username: "sam@example.test",
          password: NEW_PASSWORD,
        });
        await exchange(signIn, clientId);
      });

      it("shows ForgotPassword's error for an unknown user", async () => {
        const { clientId } = await setupPool(Cognito());
        const res = await post("/forgotPassword", {
          client_id: clientId,
          ...OAUTH,
          username: "nobody@example.test",
        });
        const html = await res.text();
        expect(html).toContain("Username/client id combination not found.");
        expect(html).toContain('value="nobody@example.test"');
      });
    });

    describe("MFA setup", () => {
      it("registers an authenticator app at sign-in when the pool requires MFA", async () => {
        const client = Cognito();
        const { userPoolId, clientId } = await setupPool(client, {
          mfa: "ON",
          required: [],
        });
        await client
          .adminCreateUser({
            UserPoolId: userPoolId,
            Username: "mfa@example.test",
            MessageAction: "SUPPRESS",
          })
          .promise();
        await client
          .adminSetUserPassword({
            UserPoolId: userPoolId,
            Username: "mfa@example.test",
            Password: PASSWORD,
            Permanent: true,
          })
          .promise();
        const signIn = () =>
          post("/oauth2/authorize", {
            client_id: clientId,
            ...OAUTH,
            username: "mfa@example.test",
            password: PASSWORD,
          });

        const setup = await (await signIn()).text();
        expect(setup).toContain("Set up an authenticator app");
        expect(setup).toContain("otpauth://totp/pages%3A");
        const secret = setup.match(/<code>([A-Z2-7]+)<\/code>/)?.[1] as string;
        const done = await post("/oauth2/authorize", {
          login_session: sessionOf(setup),
          code: generate(secret),
        });
        await exchange(done, clientId);

        const user = await client
          .adminGetUser({
            UserPoolId: userPoolId,
            Username: "mfa@example.test",
          })
          .promise();
        expect(user.UserMFASettingList).toEqual(["SOFTWARE_TOKEN_MFA"]);
        expect(user.PreferredMfaSetting).toBe("SOFTWARE_TOKEN_MFA");

        const again = await (await signIn()).text();
        expect(again).toContain("Enter the code from your authenticator app.");
      });
    });
  }),
);

describe(
  "Hosted UI pages with triggers",
  withCognitoSdk(
    (Cognito, { serverUrl, codeLog }) => {
      const { post, exchange } = pages(serverUrl);

      beforeEach(() => {
        handlers = {};
        invocations = [];
      });

      it("runs PreSignUp and PostConfirmation, and an auto-confirmed sign-up goes straight to the redirect", async () => {
        handlers = {
          PreSignUp: (event) => {
            event.response.autoConfirmUser = true;
            event.response.autoVerifyEmail = true;
          },
          PostConfirmation: () => {},
          PreAuthentication: () => {},
          PostAuthentication: () => {},
        };
        const { clientId } = await setupPool(Cognito(), { required: [] });
        const res = await post("/signup", {
          client_id: clientId,
          ...OAUTH,
          username: "auto@example.test",
          password: PASSWORD,
        });
        await exchange(res, clientId);
        expect(sourcesOf("PreSignUp")).toEqual(["PreSignUp_SignUp"]);
        expect(sourcesOf("PostConfirmation")).toEqual([
          "PostConfirmation_ConfirmSignUp",
        ]);
        expect(sourcesOf("PreAuthentication")).toEqual([
          "PreAuthentication_Authentication",
        ]);
        expect(sourcesOf("PostAuthentication")).toEqual([
          "PostAuthentication_Authentication",
        ]);
        expect(codeLog().list()).toHaveLength(0);
      });

      it("shows a PreSignUp rejection on the form", async () => {
        handlers = {
          PreSignUp: () => {
            throw new Error("Sign-ups are closed");
          },
        };
        const { clientId } = await setupPool(Cognito(), { required: [] });
        const html = await (
          await post("/signup", {
            client_id: clientId,
            ...OAUTH,
            username: "closed@example.test",
            password: PASSWORD,
          })
        ).text();
        expect(html).toContain("PreSignUp failed with error");
        expect(html).toContain('action="/signup"');
      });

      it("runs CustomMessage for the sign-up code", async () => {
        handlers = { CustomMessage: () => {} };
        const { clientId } = await setupPool(Cognito(), { required: [] });
        await post("/signup", {
          client_id: clientId,
          ...OAUTH,
          username: "custom@example.test",
          password: PASSWORD,
        });
        expect(sourcesOf("CustomMessage")).toEqual(["CustomMessage_SignUp"]);
      });

      it("migrates an unknown user through UserMigration_ForgotPassword", async () => {
        handlers = {
          UserMigration: (event) => {
            event.response.userAttributes = {
              email: event.userName,
              email_verified: "true",
            };
          },
        };
        const client = Cognito();
        const { userPoolId, clientId } = await setupPool(client, {
          required: [],
        });
        const page = await (
          await post("/forgotPassword", {
            client_id: clientId,
            ...OAUTH,
            username: "legacy@example.test",
          })
        ).text();
        expect(sourcesOf("UserMigration")).toEqual([
          "UserMigration_ForgotPassword",
        ]);
        expect(invocations[0].event.request.password).toBeUndefined();
        const migrated = await client
          .adminGetUser({
            UserPoolId: userPoolId,
            Username: "legacy@example.test",
          })
          .promise();
        expect(migrated.UserStatus).toBe("RESET_REQUIRED");

        const code = codeLog()
          .list()
          .find((e) => e.type === "FORGOT_PASSWORD")?.code as string;
        await post("/confirmForgotPassword", {
          login_session: sessionOf(page),
          code,
          new_password: NEW_PASSWORD,
          confirm_password: NEW_PASSWORD,
        });
        const signIn = await post("/oauth2/authorize", {
          client_id: clientId,
          ...OAUTH,
          username: "legacy@example.test",
          password: NEW_PASSWORD,
        });
        await exchange(signIn, clientId);
      });
    },
    { lambda },
  ),
);
