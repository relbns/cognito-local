import type { CognitoIdentityServiceProvider } from "aws-sdk";
import jwt from "jsonwebtoken";
import { beforeEach, describe, expect, it } from "vitest";
import { fakeLambdaClient } from "../../src/__tests__/fakeLambdaClient";
import { LambdaService } from "../../src/services";
import { withCognitoSdk } from "./setup";

type TriggerName =
  | "PostAuthentication"
  | "PostConfirmation"
  | "PreTokenGeneration";

type TriggerEvent = {
  userPoolId: string;
  userName: string;
  request: Record<string, any>;
  response: Record<string, any>;
};

const CALLBACK = "http://localhost:9876/cb";
const PASSWORD = "Password1!";
const ADMIN_SCOPE = "aws.cognito.signin.user.admin";

let sdk: CognitoIdentityServiceProvider;
let changingTrigger: TriggerName | undefined;

const markEmailVerified = (event: TriggerEvent) =>
  sdk
    .adminUpdateUserAttributes({
      UserPoolId: event.userPoolId,
      Username: event.userName,
      UserAttributes: [{ Name: "email_verified", Value: "true" }],
    })
    .promise();

const customAuthHandlers: Record<string, (event: TriggerEvent) => void> = {
  DefineAuthChallenge(event) {
    const answered = event.request.session.at(-1)?.challengeResult === true;
    event.response.issueTokens = answered;
    event.response.failAuthentication = false;
    if (!answered) event.response.challengeName = "CUSTOM_CHALLENGE";
  },
  CreateAuthChallenge(event) {
    event.response.publicChallengeParameters = {};
    event.response.privateChallengeParameters = { answer: "123456" };
  },
  VerifyAuthChallengeResponse(event) {
    event.response.answerCorrect =
      event.request.challengeAnswer ===
      event.request.privateChallengeParameters.answer;
  },
};

const triggerNames = [
  "PostAuthentication",
  "PostConfirmation",
  "PreTokenGeneration",
  ...Object.keys(customAuthHandlers),
];

const lambda = () =>
  new LambdaService(
    Object.fromEntries(triggerNames.map((name) => [name, name])),
    fakeLambdaClient(async (functionName, event: TriggerEvent) => {
      if (functionName === changingTrigger) {
        await markEmailVerified(event);
      }
      customAuthHandlers[functionName]?.(event);
      return event;
    }),
  );

const emailVerified = async (
  client: CognitoIdentityServiceProvider,
  userPoolId: string,
  username: string,
) => {
  const user = await client
    .adminGetUser({ UserPoolId: userPoolId, Username: username })
    .promise();
  return user.UserAttributes?.find((a) => a.Name === "email_verified")?.Value;
};

const setupPool = async (client: CognitoIdentityServiceProvider) => {
  const pool = await client.createUserPool({ PoolName: "test" }).promise();
  const userPoolId = pool.UserPool?.Id as string;
  const upc = await client
    .createUserPoolClient({
      UserPoolId: userPoolId,
      ClientName: "test",
      AllowedOAuthFlowsUserPoolClient: true,
      AllowedOAuthFlows: ["code", "implicit"],
      AllowedOAuthScopes: ["openid", "email", ADMIN_SCOPE],
      CallbackURLs: [CALLBACK],
      SupportedIdentityProviders: ["COGNITO", "Google"],
    })
    .promise();
  const clientId = upc.UserPoolClient?.ClientId as string;
  await client
    .adminCreateUser({
      UserPoolId: userPoolId,
      Username: "jane",
      TemporaryPassword: "Temp1234!",
      UserAttributes: [{ Name: "email", Value: "jane@example.com" }],
      MessageAction: "SUPPRESS",
    })
    .promise();
  return { userPoolId, clientId };
};

const setPermanentPassword = (
  client: CognitoIdentityServiceProvider,
  userPoolId: string,
) =>
  client
    .adminSetUserPassword({
      UserPoolId: userPoolId,
      Username: "jane",
      Password: PASSWORD,
      Permanent: true,
    })
    .promise();

const expectRefreshKeepsChange = async (
  client: CognitoIdentityServiceProvider,
  clientId: string,
  refreshToken: string | undefined,
) => {
  expect(refreshToken).toBeTruthy();
  const refreshed = await client
    .initiateAuth({
      ClientId: clientId,
      AuthFlow: "REFRESH_TOKEN_AUTH",
      AuthParameters: { REFRESH_TOKEN: refreshToken as string },
    })
    .promise();
  const idToken = jwt.decode(
    refreshed.AuthenticationResult?.IdToken as string,
  ) as Record<string, unknown>;
  expect(idToken.email_verified).toBe(true);
};

const hostedLogin = async (
  serverUrl: string,
  clientId: string,
  responseType: "code" | "token",
) => {
  const res = await fetch(`${serverUrl}/oauth2/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientId,
      redirect_uri: CALLBACK,
      response_type: responseType,
      scope: `openid email ${ADMIN_SCOPE}`,
      username: "jane",
      password: PASSWORD,
    }).toString(),
    redirect: "manual",
  });
  expect(res.status).toBe(302);
  return new URL(res.headers.get("location") as string);
};

describe(
  "User changes made by triggers survive token issuing",
  withCognitoSdk(
    (Cognito, { serverUrl }) => {
      beforeEach(() => {
        sdk = Cognito();
        changingTrigger = undefined;
      });

      it("InitiateAuth USER_PASSWORD_AUTH keeps a PostAuthentication change", async () => {
        const { userPoolId, clientId } = await setupPool(sdk);
        await setPermanentPassword(sdk, userPoolId);
        changingTrigger = "PostAuthentication";

        const result = await sdk
          .initiateAuth({
            ClientId: clientId,
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: { USERNAME: "jane", PASSWORD },
          })
          .promise();

        expect(await emailVerified(sdk, userPoolId, "jane")).toBe("true");
        await expectRefreshKeepsChange(
          sdk,
          clientId,
          result.AuthenticationResult?.RefreshToken,
        );
      });

      it("AdminInitiateAuth ADMIN_USER_PASSWORD_AUTH keeps a PostAuthentication change", async () => {
        const { userPoolId, clientId } = await setupPool(sdk);
        await setPermanentPassword(sdk, userPoolId);
        changingTrigger = "PostAuthentication";

        const result = await sdk
          .adminInitiateAuth({
            UserPoolId: userPoolId,
            ClientId: clientId,
            AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
            AuthParameters: { USERNAME: "jane", PASSWORD },
          })
          .promise();

        expect(await emailVerified(sdk, userPoolId, "jane")).toBe("true");
        await expectRefreshKeepsChange(
          sdk,
          clientId,
          result.AuthenticationResult?.RefreshToken,
        );
      });

      it("AdminInitiateAuth keeps a PreTokenGeneration change", async () => {
        const { userPoolId, clientId } = await setupPool(sdk);
        await setPermanentPassword(sdk, userPoolId);
        changingTrigger = "PreTokenGeneration";

        const result = await sdk
          .adminInitiateAuth({
            UserPoolId: userPoolId,
            ClientId: clientId,
            AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
            AuthParameters: { USERNAME: "jane", PASSWORD },
          })
          .promise();

        expect(await emailVerified(sdk, userPoolId, "jane")).toBe("true");
        await expectRefreshKeepsChange(
          sdk,
          clientId,
          result.AuthenticationResult?.RefreshToken,
        );
      });

      it("CUSTOM_AUTH keeps a PostAuthentication change", async () => {
        const { userPoolId, clientId } = await setupPool(sdk);
        await setPermanentPassword(sdk, userPoolId);
        changingTrigger = "PostAuthentication";

        const challenge = await sdk
          .initiateAuth({
            ClientId: clientId,
            AuthFlow: "CUSTOM_AUTH",
            AuthParameters: { USERNAME: "jane" },
          })
          .promise();
        const result = await sdk
          .respondToAuthChallenge({
            ClientId: clientId,
            ChallengeName: "CUSTOM_CHALLENGE",
            Session: challenge.Session,
            ChallengeResponses: { USERNAME: "jane", ANSWER: "123456" },
          })
          .promise();

        expect(await emailVerified(sdk, userPoolId, "jane")).toBe("true");
        await expectRefreshKeepsChange(
          sdk,
          clientId,
          result.AuthenticationResult?.RefreshToken,
        );
      });

      it("RespondToAuthChallenge NEW_PASSWORD_REQUIRED keeps a PostAuthentication change", async () => {
        const { userPoolId, clientId } = await setupPool(sdk);
        changingTrigger = "PostAuthentication";

        const challenge = await sdk
          .initiateAuth({
            ClientId: clientId,
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: { USERNAME: "jane", PASSWORD: "Temp1234!" },
          })
          .promise();
        const result = await sdk
          .respondToAuthChallenge({
            ClientId: clientId,
            ChallengeName: "NEW_PASSWORD_REQUIRED",
            Session: challenge.Session,
            ChallengeResponses: { USERNAME: "jane", NEW_PASSWORD: PASSWORD },
          })
          .promise();

        expect(await emailVerified(sdk, userPoolId, "jane")).toBe("true");
        await expectRefreshKeepsChange(
          sdk,
          clientId,
          result.AuthenticationResult?.RefreshToken,
        );
      });

      it("AdminRespondToAuthChallenge NEW_PASSWORD_REQUIRED keeps a PostAuthentication change", async () => {
        const { userPoolId, clientId } = await setupPool(sdk);
        changingTrigger = "PostAuthentication";

        const result = await sdk
          .adminRespondToAuthChallenge({
            UserPoolId: userPoolId,
            ClientId: clientId,
            ChallengeName: "NEW_PASSWORD_REQUIRED",
            Session: "new-password-session",
            ChallengeResponses: { USERNAME: "jane", NEW_PASSWORD: PASSWORD },
          })
          .promise();

        expect(await emailVerified(sdk, userPoolId, "jane")).toBe("true");
        await expectRefreshKeepsChange(
          sdk,
          clientId,
          result.AuthenticationResult?.RefreshToken,
        );
      });

      it("the hosted login code grant keeps a PreTokenGeneration change", async () => {
        const { userPoolId, clientId } = await setupPool(sdk);
        await setPermanentPassword(sdk, userPoolId);
        changingTrigger = "PreTokenGeneration";

        const redirect = await hostedLogin(serverUrl(), clientId, "code");
        const tokenRes = await fetch(`${serverUrl()}/oauth2/token`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            client_id: clientId,
            redirect_uri: CALLBACK,
            code: redirect.searchParams.get("code") as string,
          }).toString(),
        });
        expect(tokenRes.status).toBe(200);
        const tokens = await tokenRes.json();

        expect(await emailVerified(sdk, userPoolId, "jane")).toBe("true");
        await expectRefreshKeepsChange(sdk, clientId, tokens.refresh_token);
      });

      it("the hosted login implicit grant keeps a PreTokenGeneration change", async () => {
        const { userPoolId, clientId } = await setupPool(sdk);
        await setPermanentPassword(sdk, userPoolId);
        changingTrigger = "PreTokenGeneration";

        const redirect = await hostedLogin(serverUrl(), clientId, "token");
        const accessToken = new URLSearchParams(redirect.hash.slice(1)).get(
          "access_token",
        ) as string;

        expect(await emailVerified(sdk, userPoolId, "jane")).toBe("true");
        const user = await sdk.getUser({ AccessToken: accessToken }).promise();
        expect(
          user.UserAttributes.find((a) => a.Name === "email_verified")?.Value,
        ).toBe("true");
      });

      it.each([
        ["PostConfirmation", "first"],
        ["PostAuthentication", "second"],
      ] as const)(
        "a federated implicit sign-in keeps a %s change (%s sign-in)",
        async (trigger, signIn) => {
          const { userPoolId, clientId } = await setupPool(sdk);
          await sdk
            .createIdentityProvider({
              UserPoolId: userPoolId,
              ProviderName: "Google",
              ProviderType: "Google",
              ProviderDetails: {
                client_id: "idp-client",
                client_secret: "idp-secret",
                authorize_scopes: "openid email",
              },
              AttributeMapping: { email: "email", username: "sub" },
            })
            .promise();

          const federatedSignIn = async () => {
            const authorize = await fetch(
              `${serverUrl()}/oauth2/authorize?identity_provider=Google` +
                `&redirect_uri=${CALLBACK}&response_type=token` +
                `&client_id=${clientId}&scope=openid+email+${ADMIN_SCOPE}`,
              { redirect: "manual" },
            );
            const idp = new URL(
              authorize.headers.get("location") as string,
              serverUrl(),
            );
            const res = await fetch(`${serverUrl()}/oauth2/idpresponse`, {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams([
                ["state", idp.searchParams.get("state") as string],
                ["subject", "1234"],
                ["claim_name", "email"],
                ["claim_value", "jane@example.com"],
              ]).toString(),
              redirect: "manual",
            });
            expect(res.status).toBe(302);
            return new URLSearchParams(
              new URL(res.headers.get("location") as string).hash.slice(1),
            ).get("access_token") as string;
          };

          if (signIn === "second") await federatedSignIn();
          changingTrigger = trigger;
          const accessToken = await federatedSignIn();

          expect(await emailVerified(sdk, userPoolId, "Google_1234")).toBe(
            "true",
          );
          await sdk.getUser({ AccessToken: accessToken }).promise();
        },
      );
    },
    { lambda },
  ),
);
