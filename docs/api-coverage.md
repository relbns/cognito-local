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
| `USER_SRP_AUTH` | InitiateAuth | No SRP is computed. The response carries random `SRP_B`, `SALT` and `SECRET_BLOCK`, and the `PASSWORD_VERIFIER` answer is accepted for any user who has a password, whatever `PASSWORD_CLAIM_SIGNATURE` holds. A wrong password signs in. Use `USER_PASSWORD_AUTH` to test password checks. |
| `REFRESH_TOKEN_AUTH`, `REFRESH_TOKEN` | both | Verifies the refresh token and returns new access and ID tokens. No new refresh token is issued. |
| `CUSTOM_AUTH` | both | Runs DefineAuthChallenge, CreateAuthChallenge and VerifyAuthChallengeResponse over several rounds, keeps the challenge history, issues a new `Session` after a wrong answer, and accepts `SRP_A` + `PASSWORD_VERIFIER` before the custom challenge (with the same SRP simplification). Sessions are in memory and expire after the client's `AuthSessionValidity`. |
| `USER_AUTH` | | Not supported. |

Challenges answered by RespondToAuthChallenge: `CUSTOM_CHALLENGE`, `PASSWORD_VERIFIER`, `SMS_MFA`,
`SOFTWARE_TOKEN_MFA`, `SELECT_MFA_TYPE`, `NEW_PASSWORD_REQUIRED` and `MFA_SETUP`.
AdminRespondToAuthChallenge answers the same set except `SELECT_MFA_TYPE`.

- `SMS_MFA` checks the code the emulator generated (on the admin UI Codes page, or fixed by `CODE`).
  `SOFTWARE_TOKEN_MFA` checks a TOTP code against the user's verified secret.
- The emulator never issues `MFA_SETUP`. A response to it marks TOTP as the user's preferred MFA
  without checking the code.
- GetTokensFromRefreshToken returns access and ID tokens only.
- GlobalSignOut, AdminUserGlobalSignOut and RevokeToken revoke tokens as described in
  [tokens.md](tokens.md#revocation).

## MFA

| Operation | Behaviour |
| --- | --- |
| AssociateSoftwareToken | Returns a TOTP secret. Takes an `AccessToken`; the `Session` form (MFA setup during sign-in) returns an error. |
| VerifySoftwareToken | Checks the TOTP code and marks the secret verified. Takes an `AccessToken` only, like AssociateSoftwareToken. |
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

Devices are stored on the user. Sign-in never returns `NewDeviceMetadata`, and the device challenges
(`DEVICE_SRP_AUTH`, `DEVICE_PASSWORD_VERIFIER`) are not supported, so a device exists only after an
explicit ConfirmDevice call with a device key of your choice.

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

Passkey sign-in needs the `USER_AUTH` flow, which is not supported.

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
| MFA required | Applies the InitiateAuth rule (pool MFA `ON`, or not `OFF` and the user has MFA). An SMS code goes to `phone_number` through message delivery and appears in the admin Codes viewer. A TOTP code is checked against the user's verified authenticator. A user with both methods and no preferred one chooses first. A user with no method set up is refused, since the form does not offer MFA setup. A wrong code shows `Invalid code or auth state for the user.` |

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
