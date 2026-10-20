import type { CognitoIdentityServiceProvider } from "aws-sdk";
import * as jwt from "jsonwebtoken";
import { describe, expect, it, vi } from "vitest";
import { UserLambdaValidationError } from "../../src/errors";
import type { Lambda } from "../../src/services";
import { withCognitoSdk } from "./setup";

const CALLBACK = "http://localhost:9999/cb";

const basicAuth = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;

async function setupPool(
  client: CognitoIdentityServiceProvider,
  supported = ["COGNITO", "Google", "ExampleOIDC"],
) {
  const pool = await client.createUserPool({ PoolName: "fed" }).promise();
  const userPoolId = pool.UserPool!.Id!;
  await client
    .createIdentityProvider({
      UserPoolId: userPoolId,
      ProviderName: "Google",
      ProviderType: "Google",
      ProviderDetails: {
        client_id: "google-client",
        client_secret: "google-secret",
        authorize_scopes: "openid email profile",
      },
      AttributeMapping: {
        email: "email",
        email_verified: "email_verified",
        name: "name",
        username: "sub",
      },
    })
    .promise();
  await client
    .createIdentityProvider({
      UserPoolId: userPoolId,
      ProviderName: "ExampleOIDC",
      ProviderType: "OIDC",
      IdpIdentifiers: ["example-oidc"],
      ProviderDetails: {
        client_id: "example-oidc-client",
        client_secret: "example-oidc-secret",
        oidc_issuer: "https://login.example.test",
        authorize_scopes: "openid email",
      },
      AttributeMapping: { email: "email", username: "sub" },
    })
    .promise();
  const upc = await client
    .createUserPoolClient({
      UserPoolId: userPoolId,
      ClientName: "idp",
      GenerateSecret: true,
      AllowedOAuthFlowsUserPoolClient: true,
      AllowedOAuthFlows: ["code"],
      AllowedOAuthScopes: ["email", "openid", "phone", "profile"],
      CallbackURLs: [CALLBACK],
      SupportedIdentityProviders: supported,
    })
    .promise();
  return {
    userPoolId,
    clientId: upc.UserPoolClient!.ClientId!,
    clientSecret: upc.UserPoolClient!.ClientSecret!,
  };
}

function hostedUiAuthorizeUrl(
  serverUrl: string,
  clientId: string,
  idp: string,
) {
  return (
    `${serverUrl}/oauth2/authorize?` +
    `identity_provider=${idp}&redirect_uri=${CALLBACK}&response_type=CODE` +
    `&client_id=${clientId}&scope=openid+email+profile+phone&state=s1`
  );
}

async function openMockIdp(serverUrl: string, authorizeUrl: string) {
  const authorize = await fetch(authorizeUrl, { redirect: "manual" });
  expect(authorize.status).toBe(302);
  const location = new URL(authorize.headers.get("location")!, serverUrl);
  expect(location.pathname).toMatch(/^\/mock-idp\/[^/]+\/authorize$/);
  const page = await fetch(location);
  expect(page.status).toBe(200);
  return {
    stateId: location.searchParams.get("state")!,
    html: await page.text(),
  };
}

async function postIdpResponse(
  serverUrl: string,
  fields: Array<[string, string]>,
): Promise<URL> {
  const res = await fetch(`${serverUrl}/oauth2/idpresponse`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields).toString(),
    redirect: "manual",
  });
  expect(res.status).toBe(302);
  return new URL(res.headers.get("location")!);
}

async function federatedSignIn(
  serverUrl: string,
  authorizeUrl: string,
  subject: string,
  claims: Array<[string, string]> = [],
): Promise<URL> {
  const { stateId } = await openMockIdp(serverUrl, authorizeUrl);
  return postIdpResponse(serverUrl, [
    ["state", stateId],
    ["subject", subject],
    ...claims.flatMap(
      ([name, value]): Array<[string, string]> => [
        ["claim_name", name],
        ["claim_value", value],
      ],
    ),
  ]);
}

async function exchange(
  serverUrl: string,
  { clientId, clientSecret }: { clientId: string; clientSecret: string },
  code: string,
) {
  const res = await fetch(`${serverUrl}/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: basicAuth(clientId, clientSecret),
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      redirect_uri: CALLBACK,
      code,
    }).toString(),
  });
  expect(res.status).toBe(200);
  const body = await res.json();
  return jwt.decode(body.id_token) as Record<string, any>;
}

const GOOGLE_CLAIMS: Array<[string, string]> = [
  ["email", "jane@gmail.com"],
  ["email_verified", "true"],
  ["name", "Jane Doe"],
];

describe(
  "Federated sign-in through the mock identity provider",
  withCognitoSdk((Cognito, { serverUrl }) => {
    it("creates Google_<sub> on first sign-in with mapped attributes and the identities claim", async () => {
      const client = Cognito();
      const app = await setupPool(client);

      const redirect = await federatedSignIn(
        serverUrl(),
        hostedUiAuthorizeUrl(serverUrl(), app.clientId, "Google"),
        "1234567890",
        GOOGLE_CLAIMS,
      );
      expect(redirect.origin + redirect.pathname).toBe(CALLBACK);
      expect(redirect.searchParams.get("state")).toBe("s1");

      const idToken = await exchange(
        serverUrl(),
        app,
        redirect.searchParams.get("code")!,
      );
      expect(idToken["cognito:username"]).toBe("Google_1234567890");
      expect(idToken.email).toBe("jane@gmail.com");
      expect(idToken.email_verified).toBe(true);
      expect(idToken.name).toBe("Jane Doe");
      expect(idToken.identities).toEqual([
        {
          userId: "1234567890",
          providerName: "Google",
          providerType: "Google",
          issuer: null,
          primary: "true",
          dateCreated: expect.stringMatching(/^\d{13}$/),
        },
      ]);

      const user = await client
        .adminGetUser({
          UserPoolId: app.userPoolId,
          Username: "Google_1234567890",
        })
        .promise();
      expect(user.UserStatus).toBe("EXTERNAL_PROVIDER");
      const identities = JSON.parse(
        user.UserAttributes!.find((a) => a.Name === "identities")!.Value!,
      );
      expect(identities[0]).toMatchObject({
        primary: true,
        userId: "1234567890",
      });
    });

    it("reuses the federated user on the second sign-in", async () => {
      const client = Cognito();
      const app = await setupPool(client);
      const url = hostedUiAuthorizeUrl(serverUrl(), app.clientId, "Google");

      const first = await exchange(
        serverUrl(),
        app,
        (
          await federatedSignIn(serverUrl(), url, "42", GOOGLE_CLAIMS)
        ).searchParams.get("code")!,
      );
      const second = await exchange(
        serverUrl(),
        app,
        (
          await federatedSignIn(serverUrl(), url, "42", [
            ["email", "jane@gmail.com"],
            ["name", "Jane Renamed"],
          ])
        ).searchParams.get("code")!,
      );

      expect(second.sub).toBe(first.sub);
      expect(second.name).toBe("Jane Renamed");
      const users = await client
        .listUsers({ UserPoolId: app.userPoolId })
        .promise();
      expect(users.Users).toHaveLength(1);
    });

    it("signs in the native user linked with AdminLinkProviderForUser", async () => {
      const client = Cognito();
      const app = await setupPool(client);
      await client
        .adminCreateUser({
          UserPoolId: app.userPoolId,
          Username: "jane",
          UserAttributes: [{ Name: "email", Value: "jane@corp.example" }],
          MessageAction: "SUPPRESS",
        })
        .promise();
      await client
        .adminLinkProviderForUser({
          UserPoolId: app.userPoolId,
          DestinationUser: {
            ProviderName: "Cognito",
            ProviderAttributeValue: "jane",
          },
          SourceUser: {
            ProviderName: "Google",
            ProviderAttributeName: "Cognito_Subject",
            ProviderAttributeValue: "777",
          },
        })
        .promise();

      const idToken = await exchange(
        serverUrl(),
        app,
        (
          await federatedSignIn(
            serverUrl(),
            hostedUiAuthorizeUrl(serverUrl(), app.clientId, "Google"),
            "777",
            GOOGLE_CLAIMS,
          )
        ).searchParams.get("code")!,
      );

      expect(idToken["cognito:username"]).toBe("jane");
      expect(idToken.email).toBe("jane@gmail.com");
      expect(idToken.identities).toEqual([
        expect.objectContaining({
          userId: "777",
          providerName: "Google",
          providerType: "Google",
          primary: "false",
        }),
      ]);
      const users = await client
        .listUsers({ UserPoolId: app.userPoolId })
        .promise();
      expect(users.Users!.map((u) => u.Username)).toEqual(["jane"]);
    });

    it("resolves an OIDC IdP by idp_identifier and records its issuer", async () => {
      const client = Cognito();
      const app = await setupPool(client);
      const url =
        `${serverUrl()}/oauth2/authorize?idp_identifier=example-oidc&redirect_uri=${CALLBACK}` +
        `&response_type=code&client_id=${app.clientId}&scope=openid+email&state=s1`;
      const { html } = await openMockIdp(serverUrl(), url);
      expect(html).toContain("https://login.example.test/authorize");

      const idToken = await exchange(
        serverUrl(),
        app,
        (
          await federatedSignIn(serverUrl(), url, "oidc-1", [
            ["email", "r@example.test"],
          ])
        ).searchParams.get("code")!,
      );
      expect(idToken["cognito:username"]).toBe("ExampleOIDC_oidc-1");
      expect(idToken.identities[0].issuer).toBe("https://login.example.test");
    });

    it("redirects the IdP error to the app with its state", async () => {
      const client = Cognito();
      const app = await setupPool(client);
      const { stateId } = await openMockIdp(
        serverUrl(),
        hostedUiAuthorizeUrl(serverUrl(), app.clientId, "Google"),
      );
      const redirect = await postIdpResponse(serverUrl(), [
        ["state", stateId],
        ["error", "access_denied"],
        ["error_description", "User cancelled the sign-in"],
      ]);
      expect(redirect.origin + redirect.pathname).toBe(CALLBACK);
      expect(redirect.searchParams.get("error")).toBe("access_denied");
      expect(redirect.searchParams.get("state")).toBe("s1");
      const users = await client
        .listUsers({ UserPoolId: app.userPoolId })
        .promise();
      expect(users.Users).toHaveLength(0);
    });

    it("rejects an IdP that is not enabled on the app client", async () => {
      const client = Cognito();
      const app = await setupPool(client, ["COGNITO"]);
      const res = await fetch(
        hostedUiAuthorizeUrl(serverUrl(), app.clientId, "Google"),
        { redirect: "manual" },
      );
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get("location")!);
      expect(location.origin + location.pathname).toBe(CALLBACK);
      expect(location.searchParams.get("error")).toBe("invalid_request");
      expect(location.searchParams.get("error_description")).toBe(
        "Identity provider Google is not enabled for this app client",
      );
      expect(location.searchParams.get("state")).toBe("s1");
    });
  }),
);

let preSignUpBehaviour: (event: any) => Promise<unknown> = async () => ({});
const lambda: Lambda = {
  enabled: vi.fn((name: string) => name === "PreSignUp"),
  invoke: vi.fn(async (_ctx: unknown, _name: string, event: unknown) =>
    preSignUpBehaviour(event),
  ) as unknown as Lambda["invoke"],
};

describe(
  "Federated sign-in and the PreSignUp trigger",
  withCognitoSdk(
    (Cognito, { serverUrl }) => {
      it("sends PreSignUp_ExternalProvider with the mapped attributes", async () => {
        const app = await setupPool(Cognito());
        const events: any[] = [];
        preSignUpBehaviour = async (event) => {
          events.push(event);
          return { autoVerifyEmail: true };
        };

        const idToken = await exchange(
          serverUrl(),
          app,
          (
            await federatedSignIn(
              serverUrl(),
              hostedUiAuthorizeUrl(serverUrl(), app.clientId, "Google"),
              "555",
              [["email", "new@gmail.com"]],
            )
          ).searchParams.get("code")!,
        );

        expect(events).toEqual([
          expect.objectContaining({
            triggerSource: "PreSignUp_ExternalProvider",
            username: "Google_555",
            clientId: app.clientId,
            userPoolId: app.userPoolId,
            userAttributes: { email: "new@gmail.com" },
          }),
        ]);
        expect(idToken.email_verified).toBe(true);
      });

      it("redirects invalid_request and creates nothing when PreSignUp throws", async () => {
        const client = Cognito();
        const app = await setupPool(client);
        preSignUpBehaviour = async () => {
          throw new UserLambdaValidationError(
            "PreSignUp failed with error Not invited.",
          );
        };

        const redirect = await federatedSignIn(
          serverUrl(),
          hostedUiAuthorizeUrl(serverUrl(), app.clientId, "Google"),
          "666",
        );
        expect(redirect.searchParams.get("error")).toBe("invalid_request");
        expect(redirect.searchParams.get("error_description")).toBe(
          "PreSignUp failed with error Not invited.",
        );
        expect(redirect.searchParams.get("state")).toBe("s1");
        const users = await client
          .listUsers({ UserPoolId: app.userPoolId })
          .promise();
        expect(users.Users).toHaveLength(0);
      });
    },
    { lambda: () => lambda },
  ),
);
