# API coverage

The emulator answers 122 Cognito User Pools operations, the keys of
[`src/targets/targets.ts`](../src/targets/targets.ts). Any other operation returns HTTP 400
`UnknownOperationException`, and an unsupported flow or challenge inside a known operation returns
HTTP 400 `CognitoLocal#Unsupported`.

Having a handler does not mean the operation behaves like AWS. Operations marked **stored only**
save their input on the pool or user and return it; nothing else in the emulator reads it. Other
simplifications are listed next to the operation. For the gaps that cut across operations, see
[Compatibility and differences from AWS](../README.md#compatibility-and-differences-from-aws).

| Area | Operations |
| --- | ---: |
| [Authentication, sign-up and sign-out](#authentication-sign-up-and-sign-out) | 14 |
| [MFA](#mfa) | 7 |
| [Users](#users) | 19 |
| [Groups](#groups) | 9 |
| [User pools and clients](#user-pools-and-clients) | 14 |
| [Identity providers](#identity-providers) | 8 |
| [Resource servers](#resource-servers) | 5 |
| [Devices](#devices) | 9 |
| [Domains and branding](#domains-and-branding) | 11 |
| [WebAuthn](#webauthn) | 4 |
| [User import jobs](#user-import-jobs) | 6 |
| [Tags, terms, risk and logging](#tags-terms-risk-and-logging) | 12 |
| [Auth events and signing certificate](#auth-events-and-signing-certificate) | 4 |
| **Total** | **122** |

## Authentication, sign-up and sign-out

InitiateAuth, AdminInitiateAuth, RespondToAuthChallenge, AdminRespondToAuthChallenge,
GetTokensFromRefreshToken, SignUp, ConfirmSignUp, ResendConfirmationCode, ForgotPassword,
ConfirmForgotPassword, AdminResetUserPassword, GlobalSignOut, AdminUserGlobalSignOut, RevokeToken.

| Auth flow | Operation | Behaviour |
| --- | --- | --- |
| `USER_PASSWORD_AUTH` | InitiateAuth | Checks the password. Runs UserMigration for an unknown user. |
| `ADMIN_USER_PASSWORD_AUTH`, `ADMIN_NO_SRP_AUTH` | AdminInitiateAuth | Checks the password. Runs UserMigration for an unknown user. |
| `USER_SRP_AUTH` | both | Runs Cognito's SRP-6a (3072-bit group, `g` = 2, SHA-256) against a verifier derived from the stored password, so the same client code that signs in to Cognito works. The `PASSWORD_VERIFIER` response is checked against `PASSWORD_CLAIM_SIGNATURE`, and a wrong password returns `NotAuthorizedException` ("Incorrect username or password."). The server state behind `SECRET_BLOCK` is in memory, can be used once, and expires after the client's `AuthSessionValidity`, so a restart invalidates a pending challenge. `Session` is optional on that response. |
| `REFRESH_TOKEN_AUTH`, `REFRESH_TOKEN` | both | Verifies the refresh token and returns new access and ID tokens. No new refresh token is issued. |
| `CUSTOM_AUTH` | both | Runs DefineAuthChallenge, CreateAuthChallenge and VerifyAuthChallengeResponse over several rounds, keeps the challenge history, issues a new `Session` after a wrong answer, and accepts `SRP_A` + `PASSWORD_VERIFIER` before the custom challenge, checking the password as `USER_SRP_AUTH` does: a wrong one ends the sign-in with `NotAuthorizedException` before DefineAuthChallenge runs again. Sessions are in memory and expire after the client's `AuthSessionValidity`. |
| `USER_AUTH` | both | Choice-based sign-in. Needs `ALLOW_USER_AUTH` in the client's `ExplicitAuthFlows` (a client without `ExplicitAuthFlows` has Cognito's defaults, which leave it out), otherwise `InvalidParameterException` ("USER_AUTH flow not enabled for this client"). The factors are `PASSWORD` and `PASSWORD_SRP` for a user with a password, plus `EMAIL_OTP` and `SMS_OTP` when the pool's `Policies.SignInPolicy.AllowedFirstAuthFactors` lists them, the user has an `email` or `phone_number`, and the user does not have to pass MFA. An available `PREFERRED_CHALLENGE` starts at once: `PASSWORD` with `PASSWORD`, `PASSWORD_SRP` with `SRP_A` (answered by `PASSWORD_VERIFIER`), or a one-time code sent through message delivery. Otherwise the response is `SELECT_CHALLENGE` with `AvailableChallenges`. `WEB_AUTHN` is never offered. |

Every flow refuses a disabled user with `NotAuthorizedException` ("User is disabled."). The password
flows check the password first, so a wrong password still returns "Incorrect username or password.".
A `FORCE_CHANGE_PASSWORD` user gets the `NEW_PASSWORD_REQUIRED` challenge only after the temporary
password matches, before MFA.

RespondToAuthChallenge and AdminRespondToAuthChallenge answer `CUSTOM_CHALLENGE`, `PASSWORD_VERIFIER`,
`SELECT_CHALLENGE`, `PASSWORD`, `PASSWORD_SRP`, `EMAIL_OTP`, `SMS_OTP`, `SMS_MFA`,
`SOFTWARE_TOKEN_MFA`, `SELECT_MFA_TYPE`, `MFA_SETUP`, `NEW_PASSWORD_REQUIRED`, `DEVICE_SRP_AUTH` and
`DEVICE_PASSWORD_VERIFIER`.

- After the first factor, a user who must pass MFA gets their preferred method, their only method,
  or `SELECT_MFA_TYPE` (`MFAS_CAN_CHOOSE`) when they have several.
- A user with no MFA method in a pool whose `MfaConfiguration` is `ON` gets `SMS_MFA` when the pool
  has an `SmsConfiguration` and the user has a `phone_number`, and `MFA_SETUP` otherwise.
  `MFAS_CAN_SETUP` lists `SMS_MFA` when the pool has an `SmsConfiguration` and `SOFTWARE_TOKEN_MFA`
  when TOTP is enabled; a pool that enables neither offers TOTP. The user registers TOTP with
  AssociateSoftwareToken and VerifySoftwareToken on the challenge `Session`, then answers `MFA_SETUP`
  with the `Session` from VerifySoftwareToken to get tokens. Answering before a code was verified
  returns `NotAuthorizedException`.
- `SMS_MFA`, `EMAIL_OTP` and `SMS_OTP` check the code the emulator sent (on the admin UI Codes page,
  or fixed by `CODE`). A wrong code returns `CodeMismatchException` and the same `Session` can be
  answered again. A correct `EMAIL_OTP` or `SMS_OTP` code marks `email_verified` or
  `phone_number_verified`. `SOFTWARE_TOKEN_MFA` checks a TOTP code against the user's verified
  secret.
- Challenge sessions are in memory, single use and expire after the client's `AuthSessionValidity`.
  The choice-based, MFA setup and device challenges refuse a `Session` that is unknown, expired or
  belongs to another user with `NotAuthorizedException` ("Invalid session for the user."). `SMS_MFA`,
  `SOFTWARE_TOKEN_MFA`, `SELECT_MFA_TYPE` and `NEW_PASSWORD_REQUIRED` also accept a `Session` the
  emulator did not issue.
- When the pool tracks devices, see [Devices](#devices), sign-in returns `NewDeviceMetadata` unless
  the request carried a `DEVICE_KEY`, and a remembered device answers `DEVICE_SRP_AUTH`.
- GetTokensFromRefreshToken returns access and ID tokens only.
- GlobalSignOut, AdminUserGlobalSignOut and RevokeToken revoke tokens as described in
  [tokens.md](tokens.md#revocation).

## MFA

| Operation | Behaviour |
| --- | --- |
| AssociateSoftwareToken | Returns a TOTP secret. With an `AccessToken` it stores the secret on the user; with the `Session` of an `MFA_SETUP` challenge it keeps the secret on the sign-in and returns a new `Session`. |
| VerifySoftwareToken | Checks the TOTP code, marks the secret verified and enables TOTP for the user. With a `Session` it also makes TOTP the preferred MFA when none is set and returns the `Session` for the `MFA_SETUP` answer. |
| SetUserMFAPreference, AdminSetUserMFAPreference | Set the user's enabled and preferred MFA. |
| SetUserPoolMfaConfig, GetUserPoolMfaConfig | Set and read `MfaConfiguration`, the SMS message and configuration, and whether TOTP is enabled. |
| GetUserAuthFactors | Returns `PASSWORD`, plus `SMS` and `TOTP` from the user's MFA settings. |

## Users

AdminCreateUser, AdminGetUser, AdminDeleteUser, AdminEnableUser, AdminDisableUser,
AdminSetUserPassword, AdminUpdateUserAttributes, AdminDeleteUserAttributes, AdminConfirmSignUp,
AdminSetUserSettings, ListUsers, GetUser, DeleteUser, ChangePassword, UpdateUserAttributes,
DeleteUserAttributes, GetUserAttributeVerificationCode, VerifyUserAttribute, SetUserSettings.

- ListUsers supports `Filter` with the `=` and `^=` operators.
- SetUserSettings and AdminSetUserSettings store `MFAOptions` and enable SMS MFA when an option uses
  SMS.
- AdminDisableUser revokes the user's tokens.

## Groups

CreateGroup, GetGroup, UpdateGroup, DeleteGroup, ListGroups, AdminAddUserToGroup,
AdminRemoveUserFromGroup, AdminListGroupsForUser, ListUsersInGroup.

Group membership appears in the `cognito:groups` claim of access and ID tokens.

## User pools and clients

CreateUserPool, DescribeUserPool, UpdateUserPool, DeleteUserPool, ListUserPools,
CreateUserPoolClient, DescribeUserPoolClient, UpdateUserPoolClient, DeleteUserPoolClient,
ListUserPoolClients, AddCustomAttributes, AddUserPoolClientSecret, DeleteUserPoolClientSecret,
ListUserPoolClientSecrets.

- A client has at most one secret. AddUserPoolClientSecret replaces it, and ListUserPoolClientSecrets
  returns that one secret.
- Pools created without `UsernameAttributes` use `UserPoolDefaults` from `config.json` (email as the
  username by default).

## Identity providers

CreateIdentityProvider, DescribeIdentityProvider, UpdateIdentityProvider, DeleteIdentityProvider,
ListIdentityProviders, GetIdentityProviderByIdentifier, AdminLinkProviderForUser,
AdminDisableProviderForUser.

Sign-in through a provider goes to the mock IdP page; see [federation.md](federation.md).
AdminLinkProviderForUser and AdminDisableProviderForUser add and remove entries in the user's
`identities` attribute.

## Resource servers

CreateResourceServer, DescribeResourceServer, UpdateResourceServer, DeleteResourceServer,
ListResourceServers.

## Devices

ConfirmDevice, GetDevice, AdminGetDevice, ForgetDevice, AdminForgetDevice, UpdateDeviceStatus,
AdminUpdateDeviceStatus, ListDevices, AdminListDevices.

A pool tracks devices when its `DeviceConfiguration` sets `ChallengeRequiredOnNewDevice` or
`DeviceOnlyRememberedOnUserPrompt`. Then:

- Every sign-in without a `DEVICE_KEY` (password, SRP, choice-based and MFA flows) returns
  `NewDeviceMetadata` with a `DeviceKey` of the form `<region>_<uuid>` and the user's
  `DeviceGroupKey`.
- ConfirmDevice accepts only a key issued to that user (otherwise `ResourceNotFoundException`, "Device
  does not exist.") and stores the `DeviceSecretVerifierConfig` the client computed. The device is
  remembered at once, or with `DeviceOnlyRememberedOnUserPrompt` it is `not_remembered` and the
  response says `UserConfirmationNecessary: true` until UpdateDeviceStatus remembers it.
- A sign-in that sends the `DEVICE_KEY` of a remembered device gets `DEVICE_SRP_AUTH` instead of tokens,
  and instead of MFA when `ChallengeRequiredOnNewDevice` is true. `DEVICE_SRP_AUTH` (with `SRP_A`) is
  answered with `DEVICE_PASSWORD_VERIFIER`, whose claim is checked with SRP-6a against the stored
  verifier, identity `DeviceGroupKey` + `DeviceKey`, as amazon-cognito-identity-js computes it.
  Tokens then come from the `TokenGeneration_AuthenticateDevice` source. A confirmed device that is
  not remembered signs in with MFA as usual, and a `DEVICE_KEY` the user does not have returns
  `ResourceNotFoundException`.
- The device operations return `DeviceAttributes` `device_status`, `device_name` and
  `dev:device_remembered_status`. List and get show confirmed devices only.

## Domains and branding

| Operation | Behaviour |
| --- | --- |
| CreateUserPoolDomain, UpdateUserPoolDomain, DeleteUserPoolDomain | Store the domain on the pool. CreateUserPoolDomain returns the domain as `CloudFrontDomain`. |
| DescribeUserPoolDomain | Finds the pool with that domain and reports it `ACTIVE`, or returns an empty description. |
| CreateManagedLoginBranding, DescribeManagedLoginBranding, DescribeManagedLoginBrandingByClient, UpdateManagedLoginBranding, DeleteManagedLoginBranding | Stored only. |
| SetUICustomization, GetUICustomization | Stored only. |

Hosted login is served by the emulator on its own host and port whatever the domain, and the login
page does not use the branding or the UI customization.

## WebAuthn

| Operation | Behaviour |
| --- | --- |
| StartWebAuthnRegistration | Returns credential creation options for the relying party `localhost`, with a random challenge. |
| CompleteWebAuthnRegistration | Stores a credential without verifying the attestation. |
| ListWebAuthnCredentials, DeleteWebAuthnCredential | List and delete the stored credentials. |

`USER_AUTH` does not offer `WEB_AUTHN`, so stored passkeys cannot be used to sign in.

## User import jobs

| Operation | Behaviour |
| --- | --- |
| CreateUserImportJob | Stores a job with a placeholder `PreSignedUrl` that accepts no upload. |
| StartUserImportJob | Marks the job `Succeeded` without importing any user. |
| StopUserImportJob | Marks the job `Stopped`. |
| DescribeUserImportJob, ListUserImportJobs | Read the stored jobs. |
| GetCSVHeader | Returns the CSV header Cognito expects. |

To load users, use a [seed file](seed-files.md) or AdminCreateUser.

## Tags, terms, risk and logging

| Operation | Behaviour |
| --- | --- |
| TagResource, UntagResource, ListTagsForResource | Store tags on the pool named by the last segment of the ARN. |
| CreateTerms, DescribeTerms, UpdateTerms, DeleteTerms, ListTerms | Stored only. The login page does not show terms. |
| SetRiskConfiguration, DescribeRiskConfiguration | Stored only. No risk evaluation runs. |
| SetLogDeliveryConfiguration, GetLogDeliveryConfiguration | Stored only. No logs are delivered. |

## Auth events and signing certificate

| Operation | Behaviour |
| --- | --- |
| AdminListUserAuthEvents | Returns an empty list. Auth events are not recorded. |
| AdminUpdateAuthEventFeedback, UpdateAuthEventFeedback | Check that the pool exists and do nothing else. |
| GetSigningCertificate | Returns a fixed placeholder string, not a usable certificate. |

## Pagination

List operations page with the parameters each operation defines (`Limit`, `MaxResults`, `NextToken`,
`PaginationToken`), 60 items per page by default. AdminListGroupsForUser, ListTagsForResource and
ListUserPoolClientSecrets return everything in one response.

## OAuth2 and OIDC endpoints

| Endpoint | Method | Behaviour |
| --- | --- | --- |
| `/oauth2/authorize` | GET, POST | `code` and `token` response types, optional PKCE (`S256` only), scopes checked against `AllowedOAuthScopes`, errors redirected to `redirect_uri`. Without `identity_provider`, or with `COGNITO`, it shows the built-in login form. With a federated `identity_provider` or `idp_identifier` it redirects to the mock IdP. |
| `/oauth2/token` | POST | `authorization_code` and `refresh_token` grants. Clients with a secret authenticate with HTTP Basic or `client_secret` in the body. `client_credentials` returns `unsupported_grant_type`. |
| `/oauth2/userInfo` | GET | OpenID Connect UserInfo for a bearer access token. |
| `/oauth2/revoke` | POST | Revokes a refresh token and the access tokens issued from it. |
| `/logout` | GET | Takes `client_id` and `logout_uri` and redirects to `logout_uri` when it is one of the client's `LogoutURLs`. The `redirect_uri` + `response_type` form is not supported. |
| `/{poolId}/.well-known/jwks.json` | GET | JSON Web Key Set. Every pool uses the same signing key. |
| `/{poolId}/.well-known/openid-configuration` | GET | OIDC discovery document, based on `TokenConfig.IssuerDomain`. |
| `/oauth2/idpresponse` | GET, POST | Return leg of a federated sign-in. |

The built-in login form checks the password, then follows the user's state:

| User | What the form does |
| --- | --- |
| Unknown | Runs UserMigration when the pool has it, and signs in the user it returns. Otherwise shows `Incorrect username or password.` |
| Disabled | Shows `User is disabled.` and issues nothing. A wrong password shows `Incorrect username or password.` first. |
| `RESET_REQUIRED` | Shows `Password reset required for the user.` |
| `UNCONFIRMED` | Shows `Incorrect username or password.` |
| `FORCE_CHANGE_PASSWORD` | Asks for a new password, checks it against the pool password policy (unless `PasswordPolicyConfig.Enforce` is `false`), stores it and marks the user `CONFIRMED`. |
| MFA required | Applies the InitiateAuth rule (pool MFA `ON`, or not `OFF` and the user has MFA). An SMS code goes to `phone_number` through message delivery and appears in the admin Codes viewer. A TOTP code is checked against the user's verified authenticator. A user with both methods and no preferred one chooses first. A user with no method set up is refused, since the form does not offer MFA setup; `src/services/mfaSetup.ts` has the helpers a setup step needs (`needsMfaSetup`, `mfaSetupOptions`, `newTotpSecret`, `totpUri`, `completeTotpSetup`). A wrong code shows `Invalid code or auth state for the user.` |

A successful sign-in runs PostAuthentication (`PostAuthentication_Authentication`) and issues the code
or tokens from the user as the trigger left it. The steps after the password are kept on the server
under a random id that expires after 3 minutes, so the username, client, redirect URI, PKCE challenge,
scope and state come from the server, not from the page. The form has no sign-up or forgot-password
pages and does not run PreAuthentication.

The emulator also serves `/mock-idp/{providerName}/authorize` (the [mock IdP](federation.md) form),
`/health`, and the admin UI and its API under `/_admin` (see [oauth-callback.md](oauth-callback.md)
for `/_admin/callback`).

## Triggers

The emulator runs these triggers, from a Lambda endpoint (`LambdaClient`) or a
[`file:` trigger](local-triggers.md):

| Trigger | Runs on |
| --- | --- |
| PreSignUp | SignUp, and the first federated sign-in (`PreSignUp_ExternalProvider`) |
| PostConfirmation | ConfirmSignUp, AdminConfirmSignUp, ConfirmForgotPassword, a SignUp that PreSignUp auto-confirms, and the first federated sign-in |
| PostAuthentication | A successful sign-in through InitiateAuth, AdminInitiateAuth, a challenge response, the built-in login form or a federated provider |
| PreTokenGeneration | Every token issue. Version 1 event: `claimsToAddOrOverride` and `claimsToSuppress` change the ID token; group overrides are ignored. |
| UserMigration | Sign-in of an unknown user, including through the built-in login form (`UserMigration_Authentication`) |
| DefineAuthChallenge, CreateAuthChallenge, VerifyAuthChallengeResponse | `CUSTOM_AUTH` |
| CustomMessage | Sign-up, resend code, forgot password, AdminCreateUser, attribute update and verification, SMS MFA |
| CustomEmailSender | Replaces message delivery for the same events except SMS MFA. The code is encrypted with the configured KMS key. |

PreAuthentication and CustomSMSSender can be configured on a pool but never run.
