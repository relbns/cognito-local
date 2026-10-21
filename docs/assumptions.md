# Unverified assumptions

Where the AWS documentation is silent or ambiguous, the emulator makes the choice below. These
behaviours are not confirmed against Cognito and can differ from it. The detailed docs describe each
one in context: [api-coverage.md](api-coverage.md), [tokens.md](tokens.md),
[federation.md](federation.md) and [local-triggers.md](local-triggers.md).

## Sign-in and challenges

- `SELECT_CHALLENGE` lists `AvailableChallenges` in the order `WEB_AUTHN`, `EMAIL_OTP`, `SMS_OTP`,
  `PASSWORD`, `PASSWORD_SRP`.
- `EMAIL_OTP` and `SMS_OTP` are not offered to a user who has to pass MFA.
- A `PREFERRED_CHALLENGE` that is not available falls back to `SELECT_CHALLENGE` without an error.
  `USER_AUTH` with no available factor returns "Incorrect username or password.".
- Under `PreventUserExistenceErrors: ENABLED`, an unknown user gets every factor the pool allows, a
  deterministic SRP salt and `USER_ID_FOR_SRP`, and a simulated `CodeDeliveryDetails`: the username
  itself when it is an email address or phone number, otherwise `+*******0000` or the username's
  first character followed by `***@e***`. An unset `PreventUserExistenceErrors` counts as `LEGACY`.
- The `Session` returned by ConfirmSignUp signs the user in once, within `AuthSessionValidity`, with
  the confirmed code as the first factor. MFA still applies.
- `MFA_SETUP` offers `SMS_MFA` before `SOFTWARE_TOKEN_MFA`, and a pool that names neither factor
  offers TOTP. VerifySoftwareToken with a `Session` makes TOTP the preferred MFA when none is set.
- `SMS_MFA`, `SOFTWARE_TOKEN_MFA`, `SELECT_MFA_TYPE` and `NEW_PASSWORD_REQUIRED` accept a `Session`
  the emulator did not issue.
- `DeviceKey` is `<region>_<uuid>` and `DeviceGroupKey` is one value per user, shared by its devices.

## Errors and messages

- Messages chosen without a reference: `Access Token does not have required scopes`,
  `REFRESH_TOKEN_AUTH flow not enabled for this client`, `Refresh Token has been revoked` for a
  rotated-out token, `User does not exist.` for a deleted user's refresh token, the RevokeToken and
  `ClientSecret` messages, and `Invalid range for token validity.` (see
  [tokens.md](tokens.md#messages-not-confirmed-against-aws)).
- "User has no attribute matching desired auto verified attributes" and "User has no attribute
  matching desired delivery mediums" (`InvalidParameterException`).
- A write to a developer-only attribute from SignUp, UpdateUserAttributes or DeleteUserAttributes
  returns `NotAuthorizedException` "A client attempted to write unauthorized attribute".
- An expired SRP or hosted login session returns "Invalid session for the user, session is
  expired.".
- `/oauth2/userInfo` errors use the `error_description` texts "Access token is expired", "Access
  token has been revoked", "User is disabled" and "Invalid access token", and a deleted user gets
  HTTP 404 `{"error":"user_not_found"}`.
- Without a CustomMessage trigger, a message carries only the code, with no default text.

## Tokens

- Refresh-token rotation keeps the session's original expiry, `RetryGracePeriodSeconds` defaults
  to 0, and a rotating client refuses `REFRESH_TOKEN_AUTH`.
- An app client without `ReadAttributes`, or with an empty list, reads every attribute except
  `custom:` and `dev:custom:` ones.
- Every pool signs with the same key, and GetSigningCertificate returns a fixed placeholder.

## Federation and hosted login

- One `cognito` session cookie (one hour, in memory) covers every pool, where Cognito sets one per
  user pool domain. Reusing that session skips PostAuthentication.
- In real mode, discovery documents and JWKS are cached for 10 minutes and fetched again for an
  unknown `kid`. Pending federated sign-ins live 10 minutes and are single use.
- Hosted login steps after the password expire after 3 minutes. The sign-up and reset pages keep
  their `login_session` for one hour.
- Federated users are named `<ProviderName>_<subject>` with the provider name as configured. The
  `identities` claim carries string values (`"primary": "true"`).
- AdminDisableProviderForUser removes the matching link and, when none is left, sets `identities`
  to an empty string.

## Passkeys

- A registration challenge is valid for 5 minutes, with `timeout` 60000. Sign-in uses `timeout`
  180000.
- A user can register at most 20 passkeys.
- Only `none` and `packed` attestation are checked, and a signature counter that stays at 0 is
  accepted.
- The relying party ID falls back to the custom domain, then to
  `<prefix>.auth.<region>.amazoncognito.com`.

## Users, attributes and clients

- A developer-only attribute is named `dev:custom:<name>`, written only by admin operations and
  never put in tokens.
- An app client has at most one secret, with the id `<ClientId>--<creation time in epoch seconds>`.
  AddUserPoolClientSecret replaces it, and ListUserPoolClientSecrets does not return its value.

## Limits and timings

- The password lockout count resets after a correct password, or after 15 minutes without an
  attempt once a lockout started.
- Password reset requests are limited to `LockoutConfig.PasswordResetAttemptsPerHour` (20 by
  default, the top of the documented 5 to 20) on a sliding hour.
- Wrong MFA and one-time codes have no attempt limit.
- Codes are 6 digits. Sign-up confirmation and password reset codes do not expire, and `EMAIL_OTP`
  and `SMS_OTP` codes last as long as the challenge session.

## Triggers

- PreAuthentication runs once for `USER_AUTH`, before any factor is chosen, including the
  ConfirmSignUp `Session` path. For an unknown user it runs only under `ENABLED`, with
  `userNotFound: true`.
- Trigger events carry `version: "0"` (PreTokenGeneration follows `LambdaVersion`),
  `region: "local"` and `callerContext.awsSdkVersion: "aws-sdk-unknown-unknown"`.
