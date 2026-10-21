# Tokens

The emulator checks tokens the way Cognito does. A token that Cognito would reject is rejected here
with the same exception and message, so the error paths of your app can be tested locally.

## Access tokens

Every operation that takes an `AccessToken` (`GetUser`, `UpdateUserAttributes`, `DeleteUser`,
`DeleteUserAttributes`, `ChangePassword`, `GlobalSignOut`, `VerifyUserAttribute`,
`GetUserAttributeVerificationCode`, `SetUserMFAPreference`, `SetUserSettings`,
`AssociateSoftwareToken`, `VerifySoftwareToken`, `ListDevices`, `GetDevice`, `ForgetDevice`,
`UpdateDeviceStatus`, `ConfirmDevice`, `GetUserAuthFactors` and the WebAuthn operations) and
`/oauth2/userInfo` verify the token, in this order:

| Check | Error (`NotAuthorizedException` unless noted) |
| --- | --- |
| It is a JWT signed with the emulator key (RS256), `token_use` is `access`, its `client_id` is an existing app client and `iss` is that client's pool | `Invalid Access Token` |
| `exp` is in the future | `Access Token has expired` |
| The user still exists (same `sub`) | `UserNotFoundException`: `User does not exist.` |
| The user is enabled | `User is disabled.` |
| Its session was not revoked | `Access Token has been revoked` |
| The scope includes `aws.cognito.signin.user.admin` (not for `userInfo`) | `Access Token does not have required scopes` |

`/oauth2/userInfo` answers HTTP 401 `{"error":"invalid_token","error_description":...}` with a
`WWW-Authenticate: Bearer` header.

## Refresh tokens

`InitiateAuth` / `AdminInitiateAuth` with `REFRESH_TOKEN_AUTH`, `GetTokensFromRefreshToken` and the
`refresh_token` grant of `/oauth2/token` check the refresh token: `Invalid Refresh Token` (bad
signature, another client or pool), `Refresh Token has expired`, `Refresh Token has been revoked`,
`User is disabled.` and `User does not exist.`. The token endpoint returns them as
`{"error":"invalid_grant","error_description":...}`.

### Refresh token rotation

With `RefreshTokenRotation: { "Feature": "ENABLED", "RetryGracePeriodSeconds": n }` on the app client
(`CreateUserPoolClient`, `UpdateUserPoolClient` or a seed file), `GetTokensFromRefreshToken` and the
`refresh_token` grant of `/oauth2/token` also return a new refresh token. The new token belongs to the
same session (`jti`, and `origin_jti` of the access and ID tokens) and keeps the expiry of the first
refresh token of the session, so rotation never extends a session.

The refresh token that was sent keeps working for `RetryGracePeriodSeconds` (0 to 60, default 0)
after its first rotation, and a retry within that time returns another new refresh token. After the
grace period it fails with `Refresh Token has been revoked` (`invalid_grant` on the token endpoint).
`REFRESH_TOKEN_AUTH` in `InitiateAuth` and `AdminInitiateAuth` is refused for such a client with
`InvalidParameterException`: `REFRESH_TOKEN_AUTH flow not enabled for this client`. Without rotation,
refreshes return access and ID tokens only and the refresh token stays valid.

## Revocation

Each sign-in starts a session. Its id is the `origin_jti` claim of the access and ID tokens and the
`jti` of the refresh token. Tokens issued by a refresh carry the same `origin_jti`.

- `GlobalSignOut` and `AdminUserGlobalSignOut` revoke every refresh token of the user and every
  access token issued before the call. A sign-in right after the sign-out works.
- `RevokeToken` and `/oauth2/revoke` revoke one refresh token and the access tokens issued from it.
  Other sessions keep working. `RevokeToken` returns `UnsupportedOperationException` when the client
  has `EnableTokenRevocation: false` (new clients default to `true`) and
  `UnsupportedTokenTypeException` for an access or ID token.
- `AdminDisableUser` revokes the user's tokens. They stay revoked after `AdminEnableUser`.

The sessions are stored on the user record in the pool's data file, so revocation survives a
restart. Tokens issued before this version have no `origin_jti`: their access tokens are refused as
revoked, and their refresh tokens still work and start a tracked session.

## Client credentials

`POST /oauth2/token` with `grant_type=client_credentials` issues an access token to an app client
(machine-to-machine). The client authenticates with HTTP Basic or `client_id` and `client_secret` in
the body, and needs a secret, `AllowedOAuthFlowsUserPoolClient: true` and `client_credentials` in
`AllowedOAuthFlows`. `scope` lists custom scopes of the pool's resource servers
(`<identifier>/<scope name>`); without it the token gets every custom scope in
`AllowedOAuthScopes`.

The response is `{"access_token", "expires_in", "token_type": "Bearer"}`, with no ID or refresh
token. The token has `sub` and `client_id` set to the client id, `token_use: "access"`, `scope`,
`auth_time`, `iat`, `exp`, `iss`, `jti` and `version: 2`, and no `username`, `cognito:groups` or
`origin_jti`. Cognito operations that take an access token refuse it (`Access Token does not have
required scopes`), and `/oauth2/userInfo` answers `invalid_token`.

| Case | Response (HTTP 400) |
| --- | --- |
| Unknown client, no secret on the client, wrong or missing secret | `invalid_client` |
| `client_credentials` not in `AllowedOAuthFlows`, or `AllowedOAuthFlowsUserPoolClient` not `true` | `{"error":"unauthorized_client"}` |
| A scope that is not a custom scope of the pool (standard scopes included), or no custom scope to grant | `{"error":"invalid_scope"}` |
| A custom scope that exists but is not in `AllowedOAuthScopes` | `{"error":"invalid_grant"}` |
| `aws_client_metadata` that is not a JSON object | `invalid_request` |

`aws_client_metadata`, a URL-encoded JSON object, becomes `request.clientMetadata` of a version 3
pre token generation event (`TokenGeneration_ClientCredentials`, `userName: "ClientCredentials"`,
`groupConfiguration: null`). Version 1 and 2 triggers do not run for this grant.

## Pre token generation

The trigger runs before every token issue. Its event `version` follows the pool's
`LambdaConfig.PreTokenGenerationConfig.LambdaVersion`: `"1"` for `V1_0` or when only
`PreTokenGeneration` is set, `"2"` for `V2_0`, `"3"` for `V3_0`.

`request.groupConfiguration` holds the user's groups (`groupsToOverride`), the role ARNs of those
groups (`iamRolesToOverride`) and `preferredRole`: the role of the group with the lowest `Precedence`,
or `null` when groups of equal precedence have different roles. Version 2 and 3 events add
`request.scopes`, the scopes of the access token.

| Response (version) | Effect |
| --- | --- |
| `claimsOverrideDetails.claimsToAddOrOverride`, `claimsToSuppress` (1) | ID token claims |
| `claimsAndScopeOverrideDetails.idTokenGeneration` (2, 3) | ID token claims; values can be strings, numbers, booleans, arrays and objects |
| `claimsAndScopeOverrideDetails.accessTokenGeneration` (2, 3) | Access token claims, plus `scopesToAdd` and `scopesToSuppress` for the `scope` claim |
| `groupOverrideDetails` (all) | Replaces `cognito:groups` in both tokens and `cognito:roles`, `cognito:preferred_role` in the ID token. `null` or `{}` removes them; leaving the key out keeps them |

A version 1 response in a version 2 or 3 event, and the reverse, is ignored. A claim that is both
suppressed and overridden is suppressed. Suppressing `cognito:groups` also removes `cognito:roles`
and `cognito:preferred_role`. The rules follow Cognito's claims reference; a change the rules refuse
is dropped without an error:

- Never changed: `sub`, `username`, `cognito:username` and every other `cognito:` claim (groups go
  through `groupOverrideDetails`), `identities`, `client_id`, `event_id`, `device_key`, `version`,
  `acr`, `amr`, `at_hash`, `auth_time`, `azp`, `exp`, `iat`, `iss`, `jti`, `nbf`, `nonce`,
  `origin_jti`, `token_use`.
- `aud`: never in the ID token; in the access token only with the app client id as value.
- `scope`: only through `scopesToAdd` and `scopesToSuppress`. A scope with a space is not added. When
  every scope is suppressed the access token has no `scope` claim.
- `dev:` attributes can be suppressed but not added.
- `email_verified`, `phone_number_verified`, `updated_at` and `address` take no object or array value
  in the ID token.

Version 3 also runs for the `client_credentials` grant (see [Client credentials](#client-credentials)).

ID tokens carry `cognito:roles` and `cognito:preferred_role` when the user's groups have a `RoleArn`,
with or without the trigger.

## Validity

Issued tokens use the app client's `AccessTokenValidity`, `IdTokenValidity`, `RefreshTokenValidity`
and `TokenValidityUnits`. Defaults are 1 hour, 1 hour and 30 days. Units default to hours for access
and ID tokens and days for refresh tokens. `ExpiresIn` (and `expires_in` on the token endpoint and
the implicit grant) is the access token lifetime in seconds. `CreateUserPoolClient` and
`UpdateUserPoolClient` refuse values outside Cognito's range (access and ID tokens 5 minutes to 1
day, refresh tokens 60 minutes to 10 years) with `InvalidParameterException`.

## SECRET_HASH

For an app client with a secret, `SignUp`, `ConfirmSignUp`, `ForgotPassword`,
`ConfirmForgotPassword` and `ResendConfirmationCode` need `SecretHash`, and `InitiateAuth`,
`AdminInitiateAuth` (`AuthParameters`) and `RespondToAuthChallenge`, `AdminRespondToAuthChallenge`
(`ChallengeResponses`) need `SECRET_HASH`:
`Base64(HMAC_SHA256(clientSecret, username + clientId))`, with the username sent in the request.
For `REFRESH_TOKEN_AUTH` the username is the user's `sub` when the pool signs in with email or phone
(`UsernameAttributes`), and the username otherwise. `RevokeToken` and `GetTokensFromRefreshToken`
need `ClientSecret`.

| Case | Error (`NotAuthorizedException`) |
| --- | --- |
| Missing | `Client <clientId> is configured for secret but secret was not received` |
| Wrong | `Unable to verify secret hash for client <clientId>` |

## Unknown operations

An `X-Amz-Target` the emulator does not know answers HTTP 400 `UnknownOperationException`, and an
operation it knows but cannot serve (an unsupported flow) answers HTTP 400
`CognitoLocal#Unsupported`. SDKs do not retry a 400.

## Turning checks off

| Key in `.cognito/config.json` | Default | `false` restores |
| --- | --- | --- |
| `TokenConfig.Verify` | `true` | Access tokens decoded without any check (a token that does not decode returns `InvalidParameterException`), refresh tokens only looked up |
| `TokenConfig.CheckSecretHash` | `true` | `SECRET_HASH`, `SecretHash` and `ClientSecret` not checked |

## Messages not confirmed against AWS

Confirmed in AWS documentation or widely reported SDK errors: `Invalid Access Token`,
`Access Token has expired`, `Access Token has been revoked`, `User is disabled.`,
`User does not exist.` (`UserNotFoundException`), `Refresh Token has expired`,
`Refresh Token has been revoked`, `Invalid Refresh Token`, and both `SECRET_HASH` messages.

Chosen without a reference: `Access Token does not have required scopes` (reported, not
documented), the `REFRESH_TOKEN_AUTH flow not enabled for this client` refusal under rotation and
`Refresh Token has been revoked` for a rotated-out token after its grace period, `NotAuthorizedException` `User does not exist.` for a deleted user's refresh token, the
`RevokeToken` messages and the `ClientSecret` errors (which reuse the `SECRET_HASH` messages), the
`userInfo` `error_description` texts, and `Invalid range for token validity.`.
