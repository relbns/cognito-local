import {
  AdminCreateUserCommand,
  AdminInitiateAuthCommand,
  AdminSetUserPasswordCommand,
  AssociateSoftwareTokenCommand,
  CognitoIdentityProviderClient,
  CompleteWebAuthnRegistrationCommand,
  CreateUserPoolClientCommand,
  CreateUserPoolCommand,
  type CreateUserPoolCommandInput,
  DeleteWebAuthnCredentialCommand,
  GetUserAuthFactorsCommand,
  GetUserPoolMfaConfigCommand,
  InitiateAuthCommand,
  InvalidParameterException,
  LimitExceededException,
  ListWebAuthnCredentialsCommand,
  NotAuthorizedException,
  ResourceNotFoundException,
  RespondToAuthChallengeCommand,
  SetUserMFAPreferenceCommand,
  SetUserPoolMfaConfigCommand,
  type SetUserPoolMfaConfigCommandInput,
  StartWebAuthnRegistrationCommand,
  VerifySoftwareTokenCommand,
  WebAuthnChallengeNotFoundException,
  WebAuthnClientMismatchException,
  WebAuthnConfigurationMissingException,
  WebAuthnCredentialNotSupportedException,
  WebAuthnNotEnabledException,
  WebAuthnOriginNotAllowedException,
  WebAuthnRelyingPartyMismatchException,
} from "@aws-sdk/client-cognito-identity-provider";
import { describe, expect, it } from "vitest";
import { ClockFake } from "../../src/__tests__/clockFake";
import {
  type CreateOptions,
  SoftwareAuthenticator,
  type SoftwareCredential,
} from "../../src/__tests__/softwareAuthenticator";
import { generate as totpCode } from "../../src/services/totp";
import { withCognitoSdk } from "../aws-sdk/setup";

const PASSWORD = "Example-Passw0rd!";
const USERNAME = "passkey-user";
const RP_ID = "example.test";
const ORIGIN = "https://example.test";
const credentials = { accessKeyId: "local", secretAccessKey: "local" };

const newClient = (endpoint: string) =>
  new CognitoIdentityProviderClient({
    endpoint,
    region: "local",
    credentials,
    maxAttempts: 1,
  });

const passkeyPool: Partial<CreateUserPoolCommandInput> = {
  Policies: {
    SignInPolicy: { AllowedFirstAuthFactors: ["PASSWORD", "WEB_AUTHN"] },
  },
};

const clock = new ClockFake(new Date("2026-01-01T00:00:00.000Z"));

describe(
  "passkeys over AWS SDK v3",
  withCognitoSdk(
    (_, { serverUrl }) => {
      const setUp = async (
        pool: Partial<CreateUserPoolCommandInput> = passkeyPool,
        mfaConfig: Partial<SetUserPoolMfaConfigCommandInput> = {
          WebAuthnConfiguration: {
            RelyingPartyId: RP_ID,
            UserVerification: "required",
          },
        },
      ) => {
        const cognito = newClient(serverUrl());
        const created = await cognito.send(
          new CreateUserPoolCommand({ PoolName: "passkeys", ...pool }),
        );
        const userPoolId = created.UserPool?.Id as string;
        await cognito.send(
          new SetUserPoolMfaConfigCommand({
            UserPoolId: userPoolId,
            ...mfaConfig,
          }),
        );
        const newAppClient = async (name: string) =>
          (
            await cognito.send(
              new CreateUserPoolClientCommand({
                UserPoolId: userPoolId,
                ClientName: name,
                ExplicitAuthFlows: [
                  "ALLOW_USER_AUTH",
                  "ALLOW_ADMIN_USER_PASSWORD_AUTH",
                  "ALLOW_REFRESH_TOKEN_AUTH",
                ],
              }),
            )
          ).UserPoolClient?.ClientId as string;
        const clientId = await newAppClient("web");
        await cognito.send(
          new AdminCreateUserCommand({
            UserPoolId: userPoolId,
            Username: USERNAME,
            MessageAction: "SUPPRESS",
            UserAttributes: [{ Name: "email", Value: "passkey@example.test" }],
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

        const passwordSignIn = async (client = clientId) => {
          const signedIn = await cognito.send(
            new InitiateAuthCommand({
              ClientId: client,
              AuthFlow: "USER_AUTH",
              AuthParameters: {
                USERNAME,
                PREFERRED_CHALLENGE: "PASSWORD",
                PASSWORD,
              },
            }),
          );
          return signedIn.AuthenticationResult?.AccessToken as string;
        };

        const authenticator = new SoftwareAuthenticator();
        const registerPasskey = async (
          accessToken: string,
          options: Partial<CreateOptions> = {},
          completeWith = accessToken,
        ): Promise<SoftwareCredential> => {
          const started = await cognito.send(
            new StartWebAuthnRegistrationCommand({ AccessToken: accessToken }),
          );
          const creation = started.CredentialCreationOptions as {
            challenge: string;
            rp: { id: string };
            user: { id: string };
          };
          const created = authenticator.create({
            rpId: creation.rp.id,
            origin: ORIGIN,
            challenge: creation.challenge,
            userHandle: creation.user.id,
            ...options,
          });
          await cognito.send(
            new CompleteWebAuthnRegistrationCommand({
              AccessToken: completeWith,
              Credential: created.response,
            }),
          );
          return created.credential;
        };

        return {
          cognito,
          userPoolId,
          clientId,
          newAppClient,
          passwordSignIn,
          authenticator,
          registerPasskey,
        };
      };

      const passkeyChallenge = (
        parameters: Record<string, string> | undefined,
      ) =>
        JSON.parse(parameters?.CREDENTIAL_REQUEST_OPTIONS ?? "{}") as {
          challenge: string;
          rpId: string;
          allowCredentials: { id: string; type: string }[];
          userVerification: string;
          timeout: number;
        };

      it("registers a passkey, lists it and signs in with it", async () => {
        const env = await setUp();
        const { cognito, clientId } = env;
        const accessToken = await env.passwordSignIn();

        const before = await cognito.send(
          new InitiateAuthCommand({
            ClientId: clientId,
            AuthFlow: "USER_AUTH",
            AuthParameters: { USERNAME },
          }),
        );
        expect(before.AvailableChallenges).toEqual([
          "PASSWORD",
          "PASSWORD_SRP",
        ]);

        const started = await cognito.send(
          new StartWebAuthnRegistrationCommand({ AccessToken: accessToken }),
        );
        expect(started.CredentialCreationOptions).toMatchObject({
          rp: { id: RP_ID, name: RP_ID },
          user: { name: USERNAME },
          pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 },
          ],
          excludeCredentials: [],
          authenticatorSelection: {
            residentKey: "required",
            userVerification: "required",
          },
        });

        const credential = await env.registerPasskey(accessToken);
        const credentialId = credential.id.toString("base64url");

        const listed = await cognito.send(
          new ListWebAuthnCredentialsCommand({ AccessToken: accessToken }),
        );
        expect(listed.Credentials).toEqual([
          {
            CredentialId: credentialId,
            FriendlyCredentialName: "Platform authenticator",
            RelyingPartyId: RP_ID,
            AuthenticatorAttachment: "platform",
            AuthenticatorTransports: ["internal"],
            CreatedAt: clock.get(),
          },
        ]);
        const factors = await cognito.send(
          new GetUserAuthFactorsCommand({ AccessToken: accessToken }),
        );
        expect(factors.ConfiguredUserAuthFactors).toContain("WEB_AUTHN");

        const select = await cognito.send(
          new InitiateAuthCommand({
            ClientId: clientId,
            AuthFlow: "USER_AUTH",
            AuthParameters: { USERNAME },
          }),
        );
        expect(select.AvailableChallenges).toEqual([
          "WEB_AUTHN",
          "PASSWORD",
          "PASSWORD_SRP",
        ]);
        const chosen = await cognito.send(
          new RespondToAuthChallengeCommand({
            ClientId: clientId,
            ChallengeName: "SELECT_CHALLENGE",
            Session: select.Session,
            ChallengeResponses: { USERNAME, ANSWER: "WEB_AUTHN" },
          }),
        );
        expect(chosen.ChallengeName).toEqual("WEB_AUTHN");
        const options = passkeyChallenge(chosen.ChallengeParameters);
        expect(options).toMatchObject({
          rpId: RP_ID,
          allowCredentials: [{ id: credentialId, type: "public-key" }],
          userVerification: "required",
          timeout: 180000,
        });

        const signedIn = await cognito.send(
          new RespondToAuthChallengeCommand({
            ClientId: clientId,
            ChallengeName: "WEB_AUTHN",
            Session: chosen.Session,
            ChallengeResponses: {
              USERNAME,
              CREDENTIAL: JSON.stringify(
                env.authenticator.get(credential, {
                  rpId: options.rpId,
                  origin: ORIGIN,
                  challenge: options.challenge,
                }),
              ),
            },
          }),
        );
        expect(signedIn.AuthenticationResult?.AccessToken).toBeTruthy();
        expect(signedIn.AuthenticationResult?.RefreshToken).toBeTruthy();
      });

      it("signs in with PREFERRED_CHALLENGE=WEB_AUTHN, refusing a wrong signature or a reused challenge", async () => {
        const env = await setUp();
        const { cognito, clientId } = env;
        const credential = await env.registerPasskey(
          await env.passwordSignIn(),
        );

        const challenge = await cognito.send(
          new InitiateAuthCommand({
            ClientId: clientId,
            AuthFlow: "USER_AUTH",
            AuthParameters: { USERNAME, PREFERRED_CHALLENGE: "WEB_AUTHN" },
          }),
        );
        expect(challenge.ChallengeName).toEqual("WEB_AUTHN");
        const options = passkeyChallenge(challenge.ChallengeParameters);
        const respond = (assertion: unknown) =>
          cognito.send(
            new RespondToAuthChallengeCommand({
              ClientId: clientId,
              ChallengeName: "WEB_AUTHN",
              Session: challenge.Session,
              ChallengeResponses: {
                USERNAME,
                CREDENTIAL: JSON.stringify(assertion),
              },
            }),
          );
        const assertion = (extra = {}) =>
          env.authenticator.get(credential, {
            rpId: RP_ID,
            origin: ORIGIN,
            challenge: options.challenge,
            ...extra,
          });

        await expect(
          respond(assertion({ badSignature: true })),
        ).rejects.toThrow(NotAuthorizedException);
        await expect(
          respond(assertion({ userVerified: false })),
        ).rejects.toThrow(NotAuthorizedException);

        const signedIn = await respond(assertion());
        expect(signedIn.AuthenticationResult?.IdToken).toBeTruthy();
        await expect(respond(assertion())).rejects.toThrow(
          NotAuthorizedException,
        );

        const admin = await cognito.send(
          new AdminInitiateAuthCommand({
            UserPoolId: env.userPoolId,
            ClientId: clientId,
            AuthFlow: "USER_AUTH",
            AuthParameters: { USERNAME, PREFERRED_CHALLENGE: "WEB_AUTHN" },
          }),
        );
        expect(admin.ChallengeName).toEqual("WEB_AUTHN");
      });

      it("deletes a passkey, which then is no longer offered", async () => {
        const env = await setUp();
        const { cognito, clientId } = env;
        const accessToken = await env.passwordSignIn();
        const credential = await env.registerPasskey(accessToken);
        const CredentialId = credential.id.toString("base64url");

        await cognito.send(
          new DeleteWebAuthnCredentialCommand({
            AccessToken: accessToken,
            CredentialId,
          }),
        );
        const listed = await cognito.send(
          new ListWebAuthnCredentialsCommand({ AccessToken: accessToken }),
        );
        expect(listed.Credentials).toEqual([]);
        await expect(
          cognito.send(
            new DeleteWebAuthnCredentialCommand({
              AccessToken: accessToken,
              CredentialId,
            }),
          ),
        ).rejects.toThrow(ResourceNotFoundException);

        const select = await cognito.send(
          new InitiateAuthCommand({
            ClientId: clientId,
            AuthFlow: "USER_AUTH",
            AuthParameters: { USERNAME, PREFERRED_CHALLENGE: "WEB_AUTHN" },
          }),
        );
        expect(select.ChallengeName).toEqual("SELECT_CHALLENGE");
        expect(select.AvailableChallenges).not.toContain("WEB_AUTHN");
      });

      it("reports the pool's passkey configuration", async () => {
        const env = await setUp();
        const config = await env.cognito.send(
          new GetUserPoolMfaConfigCommand({ UserPoolId: env.userPoolId }),
        );
        expect(config.WebAuthnConfiguration).toEqual({
          RelyingPartyId: RP_ID,
          UserVerification: "required",
          FactorConfiguration: "SINGLE_FACTOR",
        });
      });

      it("refuses registration when passkeys are off or the pool has no relying party", async () => {
        const off = await setUp({});
        await expect(
          off.cognito.send(
            new StartWebAuthnRegistrationCommand({
              AccessToken: await off.passwordSignIn(),
            }),
          ),
        ).rejects.toThrow(WebAuthnNotEnabledException);

        const noRp = await setUp(passkeyPool, {});
        await expect(
          noRp.cognito.send(
            new StartWebAuthnRegistrationCommand({
              AccessToken: await noRp.passwordSignIn(),
            }),
          ),
        ).rejects.toThrow(WebAuthnConfigurationMissingException);
      });

      it("refuses a registration that does not match its challenge, client, origin or relying party", async () => {
        const env = await setUp();
        const { cognito } = env;
        const accessToken = await env.passwordSignIn();

        await expect(
          cognito.send(
            new CompleteWebAuthnRegistrationCommand({
              AccessToken: accessToken,
              Credential: env.authenticator.create({
                rpId: RP_ID,
                origin: ORIGIN,
                challenge: "bm8tY2hhbGxlbmdl",
              }).response,
            }),
          ),
        ).rejects.toThrow(WebAuthnChallengeNotFoundException);

        const otherClient = await env.newAppClient("other");
        const otherToken = await env.passwordSignIn(otherClient);
        await expect(
          env.registerPasskey(accessToken, {}, otherToken),
        ).rejects.toThrow(WebAuthnClientMismatchException);
        await expect(
          env.registerPasskey(accessToken, { origin: "https://example.org" }),
        ).rejects.toThrow(WebAuthnOriginNotAllowedException);
        await expect(
          env.registerPasskey(accessToken, { rpId: "other.example.test" }),
        ).rejects.toThrow(WebAuthnRelyingPartyMismatchException);
        await expect(
          env.registerPasskey(accessToken, { userVerified: false }),
        ).rejects.toThrow(WebAuthnCredentialNotSupportedException);
        await expect(
          env.registerPasskey(accessToken, { challenge: "d3Jvbmc" }),
        ).rejects.toThrow(WebAuthnChallengeNotFoundException);
        await expect(
          cognito.send(
            new CompleteWebAuthnRegistrationCommand({
              AccessToken: accessToken,
              Credential: "not json",
            }),
          ),
        ).rejects.toThrow(InvalidParameterException);
      });

      it("expires the registration challenge", async () => {
        const env = await setUp();
        const accessToken = await env.passwordSignIn();
        const started = await env.cognito.send(
          new StartWebAuthnRegistrationCommand({ AccessToken: accessToken }),
        );
        const creation = started.CredentialCreationOptions as {
          challenge: string;
        };
        clock.advanceBy(5 * 60_000 + 1);
        await expect(
          env.cognito.send(
            new CompleteWebAuthnRegistrationCommand({
              AccessToken: accessToken,
              Credential: env.authenticator.create({
                rpId: RP_ID,
                origin: ORIGIN,
                challenge: creation.challenge,
              }).response,
            }),
          ),
        ).rejects.toThrow(WebAuthnChallengeNotFoundException);
      });

      it("allows at most 20 passkeys per user", async () => {
        const env = await setUp();
        const accessToken = await env.passwordSignIn();
        for (let i = 0; i < 20; i++) {
          await env.registerPasskey(accessToken);
        }
        await expect(
          env.cognito.send(
            new StartWebAuthnRegistrationCommand({ AccessToken: accessToken }),
          ),
        ).rejects.toThrow(LimitExceededException);
      });

      describe("with MFA", () => {
        const enableTotp = async (
          cognito: CognitoIdentityProviderClient,
          accessToken: string,
        ) => {
          const associated = await cognito.send(
            new AssociateSoftwareTokenCommand({ AccessToken: accessToken }),
          );
          await cognito.send(
            new VerifySoftwareTokenCommand({
              AccessToken: accessToken,
              UserCode: totpCode(associated.SecretCode as string),
            }),
          );
          await cognito.send(
            new SetUserMFAPreferenceCommand({
              AccessToken: accessToken,
              SoftwareTokenMfaSettings: { Enabled: true, PreferredMfa: true },
            }),
          );
        };

        it("does not offer a passkey to a user who must pass MFA", async () => {
          const env = await setUp({
            ...passkeyPool,
            MfaConfiguration: "OPTIONAL",
          });
          const accessToken = await env.passwordSignIn();
          await env.registerPasskey(accessToken);
          await enableTotp(env.cognito, accessToken);

          const select = await env.cognito.send(
            new InitiateAuthCommand({
              ClientId: env.clientId,
              AuthFlow: "USER_AUTH",
              AuthParameters: { USERNAME },
            }),
          );
          expect(select.AvailableChallenges).toEqual([
            "PASSWORD",
            "PASSWORD_SRP",
          ]);
          await expect(
            env.cognito.send(
              new SetUserMFAPreferenceCommand({
                AccessToken: accessToken,
                WebAuthnMfaSettings: { Enabled: true },
              }),
            ),
          ).rejects.toThrow(InvalidParameterException);
        });

        it("lets a verified passkey satisfy MFA with passkey MFA", async () => {
          const env = await setUp(
            { ...passkeyPool, MfaConfiguration: "OPTIONAL" },
            {
              WebAuthnConfiguration: {
                RelyingPartyId: RP_ID,
                UserVerification: "preferred",
                FactorConfiguration: "MULTI_FACTOR_WITH_USER_VERIFICATION",
              },
            },
          );
          const accessToken = await env.passwordSignIn();
          const credential = await env.registerPasskey(accessToken, {
            userVerified: false,
          });
          await expect(
            env.cognito.send(
              new SetUserMFAPreferenceCommand({
                AccessToken: accessToken,
                WebAuthnMfaSettings: { Enabled: true },
              }),
            ),
          ).rejects.toThrow(InvalidParameterException);
          await enableTotp(env.cognito, accessToken);
          await env.cognito.send(
            new SetUserMFAPreferenceCommand({
              AccessToken: accessToken,
              WebAuthnMfaSettings: { Enabled: true },
            }),
          );

          const challenge = await env.cognito.send(
            new InitiateAuthCommand({
              ClientId: env.clientId,
              AuthFlow: "USER_AUTH",
              AuthParameters: { USERNAME, PREFERRED_CHALLENGE: "WEB_AUTHN" },
            }),
          );
          const options = passkeyChallenge(challenge.ChallengeParameters);
          expect(options.userVerification).toEqual("required");
          const respond = (userVerified: boolean) =>
            env.cognito.send(
              new RespondToAuthChallengeCommand({
                ClientId: env.clientId,
                ChallengeName: "WEB_AUTHN",
                Session: challenge.Session,
                ChallengeResponses: {
                  USERNAME,
                  CREDENTIAL: JSON.stringify(
                    env.authenticator.get(credential, {
                      rpId: RP_ID,
                      origin: ORIGIN,
                      challenge: options.challenge,
                      userVerified,
                    }),
                  ),
                },
              }),
            );
          await expect(respond(false)).rejects.toThrow(NotAuthorizedException);
          const signedIn = await respond(true);
          expect(signedIn.ChallengeName).toBeUndefined();
          expect(signedIn.AuthenticationResult?.AccessToken).toBeTruthy();
        });
      });
    },
    { clock },
  ),
);
