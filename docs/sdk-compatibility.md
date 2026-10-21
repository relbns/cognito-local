# SDK compatibility

cognito-local speaks the Cognito User Pools wire protocol: AWS JSON 1.1 over `POST /`, with the
operation in `X-Amz-Target: AWSCognitoIdentityProviderService.<Operation>`. Any SDK that can send
that protocol to a custom endpoint can use the emulator. The emulator does not check SigV4
signatures, so any non-empty credentials and any region work.

## Tested SDKs

Tested on 2026-10-20.

| SDK | Version | How it is tested | Result |
| --- | --- | --- | --- |
| AWS SDK for JavaScript v2 (`aws-sdk`, dev dependency) | 2.1145.0 | `integration-tests/aws-sdk/`, 47 files, run by `npm test` | pass |
| AWS SDK for JavaScript v3 (`@aws-sdk/client-cognito-identity-provider`) | 3.1153.0 | `integration-tests/sdk-v3/`, 25 tests, run by `npm test` | pass |
| amazon-cognito-identity-js (dev dependency) | 6.3.22 | `integration-tests/aws-sdk/srpAuth.test.ts` and `integration-tests/sdk-v3/authFlows.test.ts`: `authenticateUser` with `USER_SRP_AUTH` and `CUSTOM_AUTH`, MFA setup, TOTP and remembered devices, run by `npm test` | pass |
| boto3 / botocore (Python 3.9) | 1.42.97 | `scripts/sdk-smoke/boto3_smoke.py`, 11 checks against a running emulator | pass |
| AWS CLI v2 | 2.34.37 | `scripts/sdk-smoke/aws-cli-smoke.sh`, 6 checks against a running emulator | pass |

The JavaScript v3 suite covers `SignUp` / `ConfirmSignUp`, `InitiateAuth` with `USER_PASSWORD_AUTH`,
`CUSTOM_AUTH` with Define/Create/Verify triggers and `RespondToAuthChallenge` (including a wrong
answer), `REFRESH_TOKEN_AUTH`, Admin user and group operations, `ForgotPassword` /
`ConfirmForgotPassword`, `ListUsers` with a filter, `UpdateUserAttributes`, `GlobalSignOut`,
timestamp parsing, `$metadata.requestId`, and endpoint resolution from
`AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER`. Errors arrive as the modeled exception classes
(`UsernameExistsException`, `NotAuthorizedException`, `AliasExistsException`,
`InvalidPasswordException`, `UserNotFoundException`) with the right `name`, `$fault: "client"` and
`$metadata.httpStatusCode` 400. `integration-tests/sdk-v3/authFlows.test.ts` covers `USER_AUTH`
(`SELECT_CHALLENGE`, `EMAIL_OTP`, `PASSWORD_SRP`, AdminInitiateAuth with `PASSWORD`, a client without
`ALLOW_USER_AUTH`), `MFA_SETUP` through AssociateSoftwareToken and VerifySoftwareToken with the
challenge `Session`, and the device operations with `NewDeviceMetadata`, ConfirmDevice and
`DEVICE_SRP_AUTH`.

The amazon-cognito-identity-js suite signs in through the client's own SRP code: the right password
signs in (also by email alias), a wrong one fails with `NotAuthorizedException` ("Incorrect username
or password."), a temporary password leads to `newPasswordRequired`, and `CUSTOM_AUTH` checks the
password before the custom challenge. In a pool that requires MFA and remembers devices, the
client's `mfaSetup` path (`associateSoftwareToken`, `verifySoftwareToken`) registers TOTP, the next
sign-in answers `totpRequired` and confirms the device from `NewDeviceMetadata`,
`setDeviceStatusRemembered` remembers it, and the sign-in after that completes `DEVICE_SRP_AUTH`
through the client's own device SRP code without a TOTP code.

The boto3 and CLI scripts cover the same core path (sign-up, password sign-in, `GetUser`, groups,
filtered `ListUsers`, the error codes and the environment endpoint). Run them against any emulator,
including the Docker image:

```bash
python3 -m venv /tmp/venv && /tmp/venv/bin/pip install boto3
/tmp/venv/bin/python scripts/sdk-smoke/boto3_smoke.py http://localhost:9229
scripts/sdk-smoke/aws-cli-smoke.sh http://localhost:9229
```

## Pointing an SDK at the emulator

The environment variable works for every SDK that supports service-specific endpoints (JavaScript
v3, boto3, AWS CLI v2, and the other current AWS SDKs):

```bash
export AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER=http://localhost:9229
export AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
```

boto3 reads `AWS_DEFAULT_REGION`, not `AWS_REGION`, and fails with `NoRegionError` without it.

Or in code:

| SDK | Setting | Tested |
| --- | --- | --- |
| JavaScript v3 | `new CognitoIdentityProviderClient({ endpoint: "http://localhost:9229" })` | yes |
| JavaScript v2 | `new AWS.CognitoIdentityServiceProvider({ endpoint: "http://localhost:9229" })` | yes |
| boto3 | `boto3.client("cognito-idp", endpoint_url="http://localhost:9229")` | yes |
| AWS CLI v2 | `aws cognito-idp <command> --endpoint-url http://localhost:9229` | yes |
| Java v2 | `CognitoIdentityProviderClient.builder().endpointOverride(URI.create("http://localhost:9229"))` | no |
| Go v2 | `cognitoidentityprovider.NewFromConfig(cfg, func(o *Options) { o.BaseEndpoint = aws.String("http://localhost:9229") })` | no |
| .NET | `new AmazonCognitoIdentityProviderClient(new AmazonCognitoIdentityProviderConfig { ServiceURL = "http://localhost:9229" })` | no |

The untested SDKs use the same protocol and are expected to work. Report what breaks.

## Fixed while building this matrix

- A wrong password in `InitiateAuth`, `AdminInitiateAuth` and `ChangePassword` returned
  `InvalidPasswordException`. It now returns `NotAuthorizedException` ("Incorrect username or
  password."), as Cognito does.
- `CreateUserPool` with `UsernameAttributes: []` kept the configured default `["email"]`, because
  arrays were merged index by index. A request's array now replaces the default.
- API responses carry `x-amzn-RequestId`, so `$metadata.requestId` (JavaScript v3) and
  `ResponseMetadata.RequestId` (boto3) are set.
- With `HOST=0.0.0.0` (or `--host 0.0.0.0`, as in the Docker image) the token issuer became
  `http://0.0.0.0:9229`. A wildcard host now maps to `http://localhost:<port>`.
- Access tokens are verified (signature, issuer, expiry, user, revocation) and a token that does not
  decode returns `NotAuthorizedException` ("Invalid Access Token"). `GlobalSignOut` revokes access
  tokens, refresh tokens expire, `ExpiresIn` follows the client's token validity, and `SECRET_HASH`
  is checked. See [tokens.md](tokens.md).
- An unknown operation returns HTTP 400 `UnknownOperationException`, and an unsupported flow HTTP
  400 `CognitoLocal#Unsupported`, so SDKs no longer retry them as a 5xx.

## Known gaps

These apply to every SDK, since they are server behaviour:

- **`USER_AUTH` does not offer `WEB_AUTHN`**, and does not take the `SESSION` parameter that signs a
  user in after ConfirmSignUp. `PASSWORD`, `PASSWORD_SRP`, `EMAIL_OTP` and `SMS_OTP` work.
- **`CUSTOM_AUTH` ignores devices.** It returns no `NewDeviceMetadata` and no final `DEVICE_SRP_AUTH`.
- **Request parameters are not validated against the API model.** A missing required parameter
  yields whatever the handler does next (for example `UserNotFoundException` for `AdminGetUser`
  without `Username`) instead of `InvalidParameterException`.
- **The default pool uses email as the username** (`UserPoolDefaults.UsernameAttributes:
  ["email"]`), where Cognito defaults to free-form usernames. Pass `UsernameAttributes: []` to
  `CreateUserPool`, or set the default in `.cognito/config.json`.
- **Error responses** use `Content-Type: application/json` with `__type` and `message` in the body
  and no `x-amzn-ErrorType` header. Every tested SDK reads the body, so this has no visible effect.
  An unexpected internal error returns 500 with an empty body, which SDKs report as an unknown
  error.

## The emulator's own AWS SDK

The emulator runs on the AWS SDK for JavaScript v3. `aws-sdk` v2, which reached end of support on
2025-09-08, is only a dev dependency, kept so the v2 integration suite keeps proving that v2 clients
work. `npm ls aws-sdk --omit=dev` is empty. The v3 clients need Node.js 20 or later, so `engines` now
says `>=20`.

| Use | Now |
| --- | --- |
| Request/response types | Model types from `@aws-sdk/client-cognito-identity-provider`. v3 types members AWS marks required as `T \| undefined`; `Present<T>` in `src/services/sdkTypes.ts` keeps the handlers' contract. Timestamps are still `Date` and still serialised as epoch seconds, so responses are byte-for-byte unchanged. |
| Lambda trigger client | `Lambda` from `@aws-sdk/client-lambda` |
| KMS for custom sender triggers | `@aws-crypto/client-node` 5.x with a v3 KMS client |
| `callerContext.awsSdkVersion` in trigger events | `aws-sdk-unknown-unknown`, the value Cognito sends (was the bundled v2 version) |
| `LambdaClient` / `KMSConfig` in `.cognito/config.json` | Mapped onto v3 client options, with a warning for every v2 key: see [aws-client-config.md](aws-client-config.md) |

Size, measured on 2026-10-20 with `npm ci --omit=dev`: production `node_modules` went from 96 MB
(of which `aws-sdk` was 74 MB) to 49 MB, and the bundled `start.js` in the Docker image from 19.8 MB
to 5.0 MB.

Newer v3 models also bring fields the v2 model never had, such as `AuthSessionValidity` on app
clients, which the emulator now honours.
