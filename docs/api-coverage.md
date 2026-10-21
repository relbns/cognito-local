# API coverage

The emulator answers 122 Cognito User Pools operations, the keys of
[`src/targets/targets.ts`](../src/targets/targets.ts). Any other operation returns HTTP 400
`UnknownOperationException`, and an unsupported flow or challenge inside a known operation returns
HTTP 400 `CognitoLocal#Unsupported`.

Before an operation runs, its input is checked against the Cognito service model, as the service
does. A missing required member, a length, pattern, enum or range violation returns HTTP 400
`InvalidParameterException` with the service's message format, for example `1 validation error
detected: Value null at 'clientId' failed to satisfy constraint: Member must not be null`. Values of
sensitive members (passwords, tokens, client IDs) are left out of the message. A JSON value of the
wrong type (a number where a string belongs) returns `SerializationException`. Members the model
does not have are ignored. `ValidationConfig.Enabled: false` in `config.json`, or
`COGNITO_LOCAL_VALIDATION=off`, turns the check off. The model is derived from botocore's
`cognito-idp` service model (Apache-2.0, see [`licenses/cognito-idp-model`](../licenses/cognito-idp-model))
by `npm run generate:validation-model`.

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
| `REFRESH_TOKEN_AUTH`, `REFRESH_TOKEN` | both | Verifies the refresh token and returns new access and ID tokens. No new refresh token is issued. A client with refresh token rotation refuses the flow with `InvalidParameterException`. |
| `CUSTOM_AUTH` | both | Runs DefineAuthChallenge, CreateAuthChallenge and VerifyAuthChallengeResponse over several rounds, keeps the challenge history, issues a new `Session` after a wrong answer, and accepts `SRP_A` + `PASSWORD_VERIFIER` before the custom challenge, checking the password as `USER_SRP_AUTH` does: a wrong one ends the sign-in with `NotAuthorizedException` before DefineAuthChallenge runs again. Sessions are in memory and expire after the client's `AuthSessionValidity`. |
| `USER_AUTH` | both | Choice-based sign-in. Needs `ALLOW_USER_AUTH` in the client's `ExplicitAuthFlows` (a client without `ExplicitAuthFlows` has Cognito's defaults, which leave it out), otherwise `InvalidParameterException` ("USER_AUTH flow not enabled for this client"). The factors are `PASSWORD` and `PASSWORD_SRP` for a user with a password, plus `EMAIL_OTP` and `SMS_OTP` when the pool's `Policies.SignInPolicy.AllowedFirstAuthFactors` lists them, the user has an `email` or `phone_number`, and the user does not have to pass MFA, plus `WEB_AUTHN` under the conditions in [WebAuthn](#webauthn). An available `PREFERRED_CHALLENGE` starts at once: `PASSWORD` with `PASSWORD`, `PASSWORD_SRP` with `SRP_A` (answered by `PASSWORD_VERIFIER`), a one-time code sent through message delivery, or the `WEB_AUTHN` challenge. Otherwise the response is `SELECT_CHALLENGE` with `AvailableChallenges`, where `ANSWER` `WEB_AUTHN` returns the `WEB_AUTHN` challenge. |

Every flow refuses a disabled user with `NotAuthorizedException` ("User is disabled."). The password
flows check the password first, so a wrong password still returns "Incorrect username or password.".
A `FORCE_CHANGE_PASSWORD` user gets the `NEW_PASSWORD_REQUIRED` challenge only after the temporary
password matches, before MFA. In the password, SRP and `USER_AUTH` flows a `RESET_REQUIRED` user
(migrated or imported) gets `PasswordResetRequiredException` before any password is checked, or
`NotAuthorizedException` ("Incorrect username or password.") when the client prevents user
existence errors.

### User existence errors

The app client's `PreventUserExistenceErrors` decides what a request for an unknown username returns,
as described in
[Managing user existence error responses](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-managing-errors.html).
Unset means `LEGACY`, the CreateUserPoolClient default.

| Operation | `LEGACY` | `ENABLED` |
| --- | --- | --- |
| `USER_PASSWORD_AUTH`, `ADMIN_USER_PASSWORD_AUTH`, `USER_AUTH` with `PASSWORD` | `UserNotFoundException` ("User does not exist.") | `NotAuthorizedException` ("Incorrect username or password.") |
| `USER_SRP_AUTH`, `USER_AUTH` with `PASSWORD_SRP` | `UserNotFoundException` | A normal `PASSWORD_VERIFIER` challenge with the same `SALT` and a UUID `USER_ID_FOR_SRP` every time for that username in that pool (RFC 5054 section 2.5.1.3). The `PASSWORD_VERIFIER` answer returns `NotAuthorizedException` ("Incorrect username or password."). |
| `USER_AUTH` | `UserNotFoundException` | `SELECT_CHALLENGE` listing every factor the pool allows (`WEB_AUTHN`, `EMAIL_OTP`, `SMS_OTP` from `AllowedFirstAuthFactors`, then `PASSWORD` and `PASSWORD_SRP`), or the preferred one. A one-time code challenge names a simulated destination and sends nothing; its answer returns `CodeMismatchException`. A `WEB_AUTHN` challenge lists no credentials and its answer returns `NotAuthorizedException`. |
| `CUSTOM_AUTH` | `UserNotFoundException` | DefineAuthChallenge, CreateAuthChallenge and VerifyAuthChallengeResponse run with `userNotFound: true`, empty `userAttributes` and the username as sent. When DefineAuthChallenge issues tokens, the sign-in fails with `NotAuthorizedException` ("Incorrect username or password."). |
| RespondToAuthChallenge, AdminRespondToAuthChallenge | `UserNotFoundException` | `NotAuthorizedException` ("Incorrect username or password."), except as described above |
| ForgotPassword | `UserNotFoundException` ("Username/client id combination not found."); a disabled user gets `NotAuthorizedException` ("User is disabled.") | `CodeDeliveryDetails` with a simulated destination, also for a disabled user or a user with no verified email or phone number; nothing is sent |
| ConfirmForgotPassword | `UserNotFoundException` ("Username/client id combination not found.") | `CodeMismatchException`, also for a disabled user |
| ResendConfirmationCode | `UserNotFoundException` ("Username/client id combination not found.") | `CodeDeliveryDetails` with a simulated destination, also for a disabled user; nothing is sent |
| ConfirmSignUp | `UserNotFoundException` ("Username/client id combination not found.") | `CodeMismatchException` |
| Built-in login form | "User does not exist." | "Incorrect username or password." |

A simulated destination is the username itself when it is an email address or a phone number, and
otherwise a masked placeholder (`u***@e***`, or `+*******0000` when the pool verifies phone numbers
first). PreAuthentication runs for an unknown user only under `ENABLED`, with `userNotFound: true`.

RespondToAuthChallenge and AdminRespondToAuthChallenge answer `CUSTOM_CHALLENGE`, `PASSWORD_VERIFIER`,
`SELECT_CHALLENGE`, `PASSWORD`, `PASSWORD_SRP`, `EMAIL_OTP`, `SMS_OTP`, `WEB_AUTHN`, `SMS_MFA`,
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
- GetTokensFromRefreshToken returns access and ID tokens, and a new refresh token when the client
  has `RefreshTokenRotation` enabled (see [tokens.md](tokens.md#refresh-token-rotation)). Its
  `ClientMetadata` reaches the pre token generation trigger.
- GlobalSignOut, AdminUserGlobalSignOut and RevokeToken revoke tokens as described in
  [tokens.md](tokens.md#revocation).
- SignUp returns `NotAuthorizedException` ("SignUp is not permitted for this user pool") when the
  pool's `AdminCreateUserConfig.AllowAdminCreateUserOnly` is `true`.
- ForgotPassword for an unknown user runs UserMigration (`UserMigration_ForgotPassword`) when the
  pool has it, and sends the code to the migrated user. Without it, or when the trigger rejects the
  user, the user is unknown, as described in [User existence errors](#user-existence-errors).

## MFA

| Operation | Behaviour |
| --- | --- |
| AssociateSoftwareToken | Returns a TOTP secret. With an `AccessToken` it stores the secret on the user; with the `Session` of an `MFA_SETUP` challenge it keeps the secret on the sign-in and returns a new `Session`. |
| VerifySoftwareToken | Checks the TOTP code, marks the secret verified and enables TOTP for the user. With a `Session` it also makes TOTP the preferred MFA when none is set and returns the `Session` for the `MFA_SETUP` answer. |
| SetUserMFAPreference, AdminSetUserMFAPreference | Set the user's enabled and preferred MFA, and passkey MFA (`WebAuthnMfaSettings`, see [WebAuthn](#webauthn)). |
| SetUserPoolMfaConfig, GetUserPoolMfaConfig | Set and read `MfaConfiguration`, the SMS message and configuration, whether TOTP is enabled, and `WebAuthnConfiguration` (`RelyingPartyId`, `UserVerification`, `FactorConfiguration`; read back with the defaults `preferred` and `SINGLE_FACTOR` once set). |
| GetUserAuthFactors | Returns `PASSWORD`, plus `SMS` and `TOTP` from the user's MFA settings, and `WEB_AUTHN` when the user has a passkey. |

## Users

AdminCreateUser, AdminGetUser, AdminDeleteUser, AdminEnableUser, AdminDisableUser,
AdminSetUserPassword, AdminUpdateUserAttributes, AdminDeleteUserAttributes, AdminConfirmSignUp,
AdminSetUserSettings, ListUsers, GetUser, DeleteUser, ChangePassword, UpdateUserAttributes,
DeleteUserAttributes, GetUserAttributeVerificationCode, VerifyUserAttribute, SetUserSettings.

- ListUsers supports `Filter` with the `=` and `^=` operators.
- SetUserSettings and AdminSetUserSettings store `MFAOptions` and enable SMS MFA when an option uses
  SMS.
- AdminDisableUser revokes the user's tokens.
- Every `Admin*` operation that takes a `Username` returns `UserNotFoundException` ("User does not
  exist.") when no user matches.
- GetUser returns only the attributes in the token's app client `ReadAttributes`, plus `sub`, when the
  client sets them (see [tokens.md](tokens.md#readattributes)).

## Groups

CreateGroup, GetGroup, UpdateGroup, DeleteGroup, ListGroups, AdminAddUserToGroup,
AdminRemoveUserFromGroup, AdminListGroupsForUser, ListUsersInGroup.

Group membership appears in the `cognito:groups` claim of access and ID tokens. The group operations
that take a `Username` accept any name the user signs in with (the username, `sub`, or an email or
phone number alias) and resolve it to the same user.

## User pools and clients

CreateUserPool, DescribeUserPool, UpdateUserPool, DeleteUserPool, ListUserPools,
CreateUserPoolClient, DescribeUserPoolClient, UpdateUserPoolClient, DeleteUserPoolClient,
ListUserPoolClients, AddCustomAttributes, AddUserPoolClientSecret, DeleteUserPoolClientSecret,
ListUserPoolClientSecrets.

- Clients store `RefreshTokenRotation`; `RetryGracePeriodSeconds` above 60, below 0 or a `Feature`
  other than `ENABLED` or `DISABLED` returns `InvalidParameterException`.
- A client has at most one secret. AddUserPoolClientSecret replaces it, and ListUserPoolClientSecrets
  returns that one secret.
- Pools created without `UsernameAttributes` use `UserPoolDefaults` from `config.json` (email as the
  username by default).
- In a pool with `AliasAttributes`, sign-in and every operation that takes a `Username` also find the
  user by `preferred_username`, or by an `email` or `phone_number` once it is verified.
- `UsernameConfiguration.CaseSensitive: false` makes every username lookup case-insensitive (sign-in,
  admin and group operations, sign-up and AdminCreateUser uniqueness), together with email as a
  username, the `email` and `preferred_username` alias uniqueness checks and the ListUsers
  `username`, `email` and `preferred_username` filters. The username is stored as given. Without
  `UsernameConfiguration`, or with `CaseSensitive: true`, lookups are exact, as with the Cognito API.
- A schema attribute with `DeveloperOnlyAttribute: true` (CreateUserPool, AddCustomAttributes) is
  named `dev:custom:<name>`. Admin operations write it; SignUp, UpdateUserAttributes and
  DeleteUserAttributes refuse it with `NotAuthorizedException` ("A client attempted to write
  unauthorized attribute"). GetUser returns it, and it is not added to tokens.

## Identity providers

CreateIdentityProvider, DescribeIdentityProvider, UpdateIdentityProvider, DeleteIdentityProvider,
ListIdentityProviders, GetIdentityProviderByIdentifier, AdminLinkProviderForUser,
AdminDisableProviderForUser.

Sign-in through a provider goes to the mock IdP page, or to the provider itself for OIDC and
social providers when `FederationConfig.Mode` is `real`; see [federation.md](federation.md).
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

Passkeys work as in Cognito: registered with an access token, used as a `USER_AUTH` first factor.
Passkeys are on when the pool's `Policies.SignInPolicy.AllowedFirstAuthFactors` lists `WEB_AUTHN`.
The relying party ID is `WebAuthnConfiguration.RelyingPartyId`, else the pool's custom domain,
else its prefix domain (`<prefix>.auth.<region>.amazoncognito.com`). For passkeys in a browser
against the emulator, set `RelyingPartyId` to the host that serves the pages, usually `localhost`.

| Operation | Behaviour |
| --- | --- |
| StartWebAuthnRegistration | Returns `CredentialCreationOptions` (`rp`, `user` with the base64url `sub` as `id`, `challenge`, ES256 and RS256 in `pubKeyCredParams`, `timeout` 60000, the user's passkeys in `excludeCredentials`, and `authenticatorSelection` with `residentKey` `required` and the pool's `UserVerification`). The challenge is kept on the user with the client of the access token and expires after 5 minutes; a new call replaces it. `WebAuthnNotEnabledException` when passkeys are off, `WebAuthnConfigurationMissingException` when there is no relying party ID, `LimitExceededException` at 20 passkeys. |
| CompleteWebAuthnRegistration | Verifies the `RegistrationResponseJSON` in `Credential`: `clientDataJSON` type `webauthn.create`, the challenge, an origin on the relying party ID or a subdomain (`https`, or `http` on `localhost`), `rpIdHash`, the user-present flag, and the user-verified flag when `UserVerification` is `required`. Checks the `none` and `packed` attestation statements (self attestation, or the signature of the first `x5c` certificate without a chain check) and accepts other formats without checking them, since Cognito does not enforce attestation. Stores the credential ID, COSE public key, signature counter, transports, authenticator attachment and creation date. |
| ListWebAuthnCredentials | Returns `CredentialId`, `FriendlyCredentialName` (from the authenticator attachment), `RelyingPartyId`, `AuthenticatorAttachment`, `AuthenticatorTransports` and `CreatedAt`, with `MaxResults` and `NextToken`. |
| DeleteWebAuthnCredential | Deletes the passkey, or returns `ResourceNotFoundException`. |

CompleteWebAuthnRegistration errors: `WebAuthnChallengeNotFoundException` (no challenge, an expired
one, or a credential for another challenge), `WebAuthnClientMismatchException` (an access token of
another client than StartWebAuthnRegistration), `WebAuthnOriginNotAllowedException`,
`WebAuthnRelyingPartyMismatchException` (another `rpIdHash`, or a relying party ID changed since
the start), `WebAuthnCredentialNotSupportedException` (an algorithm other than ES256 and RS256, or
no user verification when it is required), and `InvalidParameterException` for a malformed
credential, a bad attestation signature or a passkey already registered.

**Sign-in.** `USER_AUTH` offers `WEB_AUTHN` when passkeys are on and the user has a passkey for the
current relying party ID, and either the user does not have to pass MFA or passkey MFA applies.
The `WEB_AUTHN` challenge carries `CREDENTIAL_REQUEST_OPTIONS`, a JSON string with `challenge`,
`rpId`, `allowCredentials` (the user's passkeys), `userVerification` and `timeout` 180000; the
challenge lives in the sign-in session. The answer is `USERNAME` and `CREDENTIAL`, an
`AuthenticationResponseJSON` string. The emulator checks the credential belongs to the user,
`clientDataJSON` type `webauthn.get`, the challenge, the origin, `rpIdHash`, the user-present flag,
the user-verified flag when required, a `userHandle` that matches the user, the signature over
`authenticatorData` and the hash of `clientDataJSON`, and a signature counter that grows (a counter
that stays 0 is accepted, for authenticators that keep none). A failed check returns
`NotAuthorizedException` and the session stays open for another try. Success continues as the other
first factors do: device authentication, PostAuthentication, PreTokenGeneration and a new device.

**Passkey MFA.** With `FactorConfiguration` `MULTI_FACTOR_WITH_USER_VERIFICATION`, a user who turned
on `WebAuthnMfaSettings` (SetUserMFAPreference or AdminSetUserMFAPreference, which need that pool
setting and another MFA method enabled for the user, else `InvalidParameterException`) gets
`WEB_AUTHN` even when MFA applies. The challenge then requires user verification and a verified
passkey signs in without an MFA challenge. Passkeys are not offered as a second factor after a
password.

**Usernameless sign-in** is not supported, as in Cognito: `USERNAME` is required to start
`USER_AUTH`, and `allowCredentials` lists that user's passkeys.

**Hosted pages.** The login page shows "Sign in with passkey" when passkeys are on and the pool has
a relying party ID. It takes the username, then a page calls `navigator.credentials.get` and posts
the result; a verified passkey signs in like a password, with the same MFA rules. `/passkeys/add`
(`client_id` and a registered `redirect_uri`) registers a passkey for the user signed in to this
browser with `navigator.credentials.create`, then redirects to `redirect_uri`. Without a browser
session it asks the user to sign in first. The managed login prompt to add a passkey right after
sign-up is not shown.

## User import jobs

| Operation | Behaviour |
| --- | --- |
| CreateUserImportJob | Creates a job in `Created` with a `PreSignedUrl` on the emulator (`PUT /_import/<pool>/<job>?X-Amz-Signature=<secret>`, built from `TokenConfig.IssuerDomain`). A `PUT` of the CSV to that URL stores it on the job, as an upload to S3 does; a wrong signature, or an upload after the job started, gets 403. Files up to 100 MB. |
| StartUserImportJob | Imports the uploaded CSV and answers with the job in `Pending`, as Cognito does. The import runs before the response, so the next DescribeUserImportJob shows `Succeeded` or `Failed` with `ImportedUsers`, `FailedUsers` and `CompletionMessage`. Only a job in `Created` can start. |
| StopUserImportJob | Marks a job that has not finished `Stopped`. |
| DescribeUserImportJob, ListUserImportJobs | Read the stored jobs. |
| GetCSVHeader | Returns Cognito's header: the standard attributes, the pool's `custom:` attributes, `cognito:mfa_enabled` and `cognito:username`. |

The import follows Cognito's CSV rules. The header names known columns in any order and must have
`cognito:username` and `cognito:mfa_enabled`; an unknown or repeated column, a missing upload or an
empty file fails the whole job. Each record becomes a user in `RESET_REQUIRED` with no password, so
sign-in returns `PasswordResetRequiredException` (`NotAuthorizedException` when the client prevents
user existence errors) until ForgotPassword and ConfirmForgotPassword set one. `cognito:mfa_enabled` `TRUE` turns on SMS MFA and needs `phone_number`. When the pool signs
in with email, the username is a generated `sub` and the email comes from `email` (or from
`cognito:username` when it is an address). No trigger runs.

A record fails, and the others still import, when it has the wrong number of fields, a
`cognito:mfa_enabled` or `*_verified` value other than `TRUE`/`FALSE`, a malformed email, phone
number or `updated_at`, a missing required attribute, an existing username or alias, a username
repeated in the file, or none of the pool's `AutoVerifiedAttributes` marked verified. Each failure
is logged as `[ERROR] Line Number <n> - <reason>`, in place of the CloudWatch log. When every record
fails the job ends `Failed` with "Too many users have failed or been skipped during the import.";
otherwise it ends `Succeeded` with "Import Job Completed Successfully.". `SkippedUsers` stays 0.

To load users with passwords, use a [seed file](seed-files.md) or AdminCreateUser.

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
| `/oauth2/authorize` | GET, POST | `code` and `token` response types, optional PKCE (`S256` only), scopes checked against `AllowedOAuthScopes`, errors redirected to `redirect_uri`. Without `identity_provider`, or with `COGNITO`, it shows the built-in login form, or issues the code at once when the browser has a session for the pool. With a federated `identity_provider` or `idp_identifier` it redirects to the mock IdP, or in [real mode](federation.md#real-providers) to the provider's authorize endpoint with `state`, `nonce` and PKCE kept server-side. `prompt=login` always shows the form, and `prompt=none` uses the session or redirects with `error=login_required`. |
| `/login` | GET | The same as `/oauth2/authorize`; `/logout` sends the browser here. |
| `/signup` | GET, POST | The sign-up page, linked from the login page. Answers HTTP 400 when the pool's `AllowAdminCreateUserOnly` is `true`. See [Hosted sign-up and password reset](#hosted-sign-up-and-password-reset). |
| `/confirm` | GET, POST | The confirmation code page after sign-up. GET with `username` opens it for an existing unconfirmed user. |
| `/resendcode` | POST | Sends a new confirmation code from the confirm page. |
| `/forgotPassword` | GET, POST | The password reset request page, linked from the login page. |
| `/confirmForgotPassword` | GET, POST | The reset code and new password page. GET with `username` opens it for a code already sent. |
| `/oauth2/token` | POST | `authorization_code`, `refresh_token` and `client_credentials` grants. Clients with a secret authenticate with HTTP Basic or `client_secret` in the body. `client_credentials` issues an M2M access token for custom scopes (see [tokens.md](tokens.md#client-credentials)). |
| `/oauth2/userInfo` | GET | OpenID Connect UserInfo for a bearer access token, limited to the app client's `ReadAttributes` when it sets them. |
| `/oauth2/revoke` | POST | Revokes a refresh token and the access tokens issued from it. |
| `/logout` | GET | Ends the browser session for the client's pool, then redirects to `logout_uri` when it is one of the client's `LogoutURLs`, or, with `redirect_uri` (one of the `CallbackURLs`) and `response_type`, to `/login` with `client_id`, `response_type`, `redirect_uri`, `state`, `scope` and `nonce`. `logout_uri` wins when both are sent. An unregistered URL answers HTTP 400 `redirect_mismatch` and keeps the session. |
| `/{poolId}/.well-known/jwks.json` | GET | JSON Web Key Set. Every pool uses the same signing key. |
| `/{poolId}/.well-known/openid-configuration` | GET | OIDC discovery document, based on `TokenConfig.IssuerDomain`, or on the request's scheme and `Host` header with `TokenConfig.IssuerFromRequest`. |
| `/oauth2/idpresponse` | GET, POST | Return leg of a federated sign-in. In real mode it exchanges the code at the provider's token endpoint (`client_secret_post`), checks the `id_token` (JWKS signature, `iss`, `aud`, `exp`, `nonce`), reads `attributes_url`, then signs the user in; failures redirect to `redirect_uri` with `error` and `error_description`. |

The built-in login form checks the password, then follows the user's state:

| User | What the form does |
| --- | --- |
| Unknown | Runs UserMigration when the pool has it, and signs in the user it returns. Otherwise shows `Incorrect username or password.` |
| Disabled | Shows `User is disabled.` and issues nothing. A wrong password shows `Incorrect username or password.` first. |
| `RESET_REQUIRED` | Shows `Password reset required for the user.` |
| `UNCONFIRMED` | Shows `Incorrect username or password.` |
| `FORCE_CHANGE_PASSWORD` | Asks for a new password, checks it against the pool password policy (unless `PasswordPolicyConfig.Enforce` is `false`), stores it and marks the user `CONFIRMED`. |
| MFA required | Applies the InitiateAuth rule (pool MFA `ON`, or not `OFF` and the user has MFA). An SMS code goes to `phone_number` through message delivery and appears in the admin Codes viewer. A TOTP code is checked against the user's verified authenticator. A user with both methods and no preferred one chooses first. A wrong code shows `Invalid code or auth state for the user.` |
| MFA `ON`, no method | Follows the `MFA_SETUP` rule of the API: when the pool has an `SmsConfiguration` and the user a `phone_number`, it sends an SMS code. Otherwise, when the pool offers TOTP, it shows an authenticator setup page with the secret key and its `otpauth://` link (no QR code). A correct code registers the authenticator as the user's enabled, preferred MFA and finishes the sign-in. When only SMS can be set up and the user has no phone number, the form shows `SMS MFA is enabled but the user has no phone number to send the code to.` |

A successful sign-in runs PostAuthentication (`PostAuthentication_Authentication`) and issues the code
or tokens from the user as the trigger left it. The steps after the password are kept on the server
under a random id that expires after 3 minutes, so the username, client, redirect URI, PKCE challenge,
scope and state come from the server, not from the page. PreAuthentication runs before the password
is checked, and an error it throws is shown on the form.

### Hosted sign-up and password reset

The login page links `/signup` (unless the pool's `AllowAdminCreateUserOnly` is `true`) and
`/forgotPassword`, with `client_id`, `response_type`, `scope`, `redirect_uri`, `state` and the PKCE
parameters in the query. Each page checks them as `/oauth2/authorize` does. The pages call the
SignUp, ConfirmSignUp, ResendConfirmationCode, ForgotPassword and ConfirmForgotPassword operations,
with `SecretHash` computed on the server for a client with a secret, so the password policy, the
required attributes, PreSignUp, PostConfirmation, UserMigration, CustomMessage, the custom sender
triggers and auto-verification behave as through the API. An error those operations return is shown
on the page.

| Page | What it does |
| --- | --- |
| Sign-up | Asks for the username (`Email` or `Phone number` when the pool signs in with one of them, `Username` otherwise), each required attribute of the pool's schema (as `requiredAttributes[<name>]`) and a password. An auto-confirmed user is signed in at once. Otherwise the confirm page opens; when the pool has no `AutoVerifiedAttributes`, no code is sent and the login page says an administrator must confirm the account. |
| Confirm | Takes the code from the delivery (also in the admin Codes viewer) and can send a new one. After a sign-up in the same browser, a correct code signs the user in (PreAuthentication, MFA, PostAuthentication) and redirects with the code or tokens. Opened from a link with `username`, it confirms the account and shows the login page. |
| Forgot password | Asks for the username and sends a reset code. |
| Reset password | Asks for the code and the new password twice, then shows the login page. |

After the first page the username and the authorize parameters are kept on the server under the
`login_session` id, for an hour, and the code pages send only that id. Fields are labelled and carry
`autocomplete` values (`username`, `email`, `tel`, `new-password`, `current-password`,
`one-time-code`).

A sign-in through the form or a federated provider sets a `cognito` cookie (HttpOnly, `SameSite=Lax`,
`Path=/`) for one hour, as Cognito's managed login does. While it is valid, `/oauth2/authorize` for
any app client of the same pool issues the code or tokens without the form and without running
PostAuthentication. A disabled or deleted user's session is ignored. A new sign-in, including after
`prompt=login`, gives a new cookie. Sessions are kept in memory, so a restart ends them, and one
cookie holds the sessions of every pool on the emulator, where Cognito gives each pool its own
domain.

The emulator also serves `/mock-idp/{providerName}/authorize` (the [mock IdP](federation.md) form),
`/health`, and the admin UI and its API under `/_admin` (see [oauth-callback.md](oauth-callback.md)
for `/_admin/callback`).

## Triggers

The emulator runs these triggers, from a Lambda endpoint (`LambdaClient`) or a
[`file:` trigger](local-triggers.md):

| Trigger | Runs on |
| --- | --- |
| PreSignUp | SignUp (with its `ValidationData` as `validationData`), AdminCreateUser (`PreSignUp_AdminCreateUser`, with `ValidationData` and `ClientMetadata`; a thrown error stops the user from being created, and `autoConfirmUser`, `autoVerifyEmail` and `autoVerifyPhone` are ignored, as in Cognito), and the first federated sign-in (`PreSignUp_ExternalProvider`). Seed files create users without it. |
| PostConfirmation | ConfirmSignUp, AdminConfirmSignUp, ConfirmForgotPassword, a SignUp that PreSignUp auto-confirms, and the first federated sign-in |
| PreAuthentication | Every sign-in attempt before the password or challenge is checked: InitiateAuth and AdminInitiateAuth with a password, SRP, `CUSTOM_AUTH` or `USER_AUTH` (once, before any factor is chosen), and the built-in login form (`PreAuthentication_Authentication`). `validationData` is the request's `ClientMetadata`. An unknown user triggers it only when the app client has `PreventUserExistenceErrors: ENABLED`, with `userNotFound: true`. A thrown error fails the sign-in with `UserLambdaValidationException` ("PreAuthentication failed with error ..."). Refresh-token and federated sign-ins do not run it. |
| PostAuthentication | A successful sign-in through InitiateAuth, AdminInitiateAuth, a challenge response, the built-in login form or a federated provider |
| PreTokenGeneration | Every token issue. Sends the event version set in `PreTokenGenerationConfig.LambdaVersion` (`V1_0`, `V2_0`, `V3_0`) with the user's groups and roles; version 2 and 3 responses customize the ID token, the access token and its scopes. See [tokens.md](tokens.md#pre-token-generation). |
| UserMigration | Sign-in of an unknown user, including through the built-in login form (`UserMigration_Authentication`). The user keeps the username they signed in with (or the `username` the trigger returns), or gets the `sub` as the username in a pool that signs in with email or phone number. The emulator generates the `sub`, stores the returned attributes, sets `CONFIRMED` only when `finalUserStatus` says so (otherwise `RESET_REQUIRED`), applies `forceAliasCreation` and `enableSMSMFA`, and sends no welcome message whatever `messageAction` says. ForgotPassword of an unknown user runs it as `UserMigration_ForgotPassword`, without `password` and `validationData`, and the user stays `RESET_REQUIRED` until ConfirmForgotPassword sets a password. |
| DefineAuthChallenge, CreateAuthChallenge, VerifyAuthChallengeResponse | `CUSTOM_AUTH` |
| CustomMessage | Sign-up, resend code, forgot password, AdminCreateUser, attribute update and verification, SMS MFA, and the `EMAIL_OTP` and `SMS_OTP` codes of `USER_AUTH` |
| CustomEmailSender | Replaces delivery of every email the emulator sends for those events, including `EMAIL_OTP` sign-in codes (`CustomEmailSender_Authentication`). The code is encrypted with the configured KMS key. |
| CustomSMSSender | Replaces delivery of every SMS: sign-up and resend codes, forgot password, AdminCreateUser temporary passwords, attribute update and verification, and SMS MFA and `SMS_OTP` sign-in codes (`CustomSMSSender_Authentication`). The event's `request.type` is `customSMSSenderRequestV1` and the code is encrypted with the configured KMS key. |

With a custom sender trigger the code still appears in the admin UI Codes viewer.
