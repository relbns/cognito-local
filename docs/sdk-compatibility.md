# SDK compatibility

cognito-local speaks the Cognito User Pools wire protocol: AWS JSON 1.1 over `POST /`, with the
operation in `X-Amz-Target: AWSCognitoIdentityProviderService.<Operation>`. Any SDK that can send
that protocol to a custom endpoint can use the emulator. The emulator does not check SigV4
signatures, so any non-empty credentials and any region work.

## Tested SDKs

Tested on 2026-10-20.

| SDK | Version | How it is tested | Result |
| --- | --- | --- | --- |
| AWS SDK for JavaScript v2 (`aws-sdk`) | 2.1145.0 | `integration-tests/aws-sdk/`, 47 files, run by `npm test` | pass |
| AWS SDK for JavaScript v3 (`@aws-sdk/client-cognito-identity-provider`) | 3.1153.0 | `integration-tests/sdk-v3/`, 12 tests, run by `npm test` | pass |
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
`$metadata.httpStatusCode` 400.

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
export AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local AWS_REGION=us-east-1
```

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
- With `HOST=0.0.0.0` the token issuer became `http://0.0.0.0:9229`. A wildcard host now yields
  `http://localhost:<port>`.

## Known gaps

These apply to every SDK, since they are server behaviour:

- **`SECRET_HASH` is not verified.** For an app client with a secret, Cognito rejects a missing or
  wrong `SECRET_HASH` with `NotAuthorizedException`. The emulator accepts both.
- **`USER_AUTH` (choice-based sign-in) is not supported.** `InitiateAuth` with `AuthFlow: USER_AUTH`
  returns `Unsupported`, and `AllowedFirstAuthFactors` on an app client is not stored.
- **Unsupported operations answer HTTP 500** with `__type: "CognitoLocal#Unsupported"`. SDKs treat
  5xx as retryable, so the call is retried (JavaScript v3 standard mode: 3 attempts) before the
  `Unsupported` error surfaces.
- **Access tokens are decoded, not verified.** Signature, expiry and revocation are not checked, so
  an access token still works after `GlobalSignOut` (its refresh tokens are revoked). A token that
  does not decode returns `InvalidParameterException`, where Cognito returns
  `NotAuthorizedException` ("Invalid Access Token").
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

## Moving the emulator itself from aws-sdk v2 to v3

The emulator depends on `aws-sdk` v2, which reached end of support on 2025-09-08. Clients are not
affected: the wire protocol is the same for every SDK. The question is maintenance and install size.

Where v2 is used today:

| Use | Where | Size of change |
| --- | --- | --- |
| Request/response types | `import type ... from "aws-sdk/clients/cognitoidentityserviceprovider"` in 120 files under `src/` | Mechanical. v3 exports the same `XxxRequest` / `XxxResponse` names. v2-only aliases such as `AttributeListType` become `AttributeType[]`. v3 types use string-literal unions and optional fields, so some narrowing will need touching up. |
| Lambda trigger client | `new AWS.Lambda(config.LambdaClient)` in `src/server/defaults.ts`, `invoke().promise()` in `src/services/lambda.ts` | Small: `@aws-sdk/client-lambda` with `InvokeCommand`; the payload becomes a `Uint8Array`. |
| KMS for custom sender triggers | `new KMS()` passed to `@aws-crypto/client-node` 3.x in `src/services/crypto.ts` | Small, with `@aws-crypto/client-node` 4.x, which takes a v3 KMS client. |
| SDK version in trigger events | `aws-sdk/package.json` in `src/services/lambda.ts` (`callerContext.awsSdkVersion`) | Trivial: a constant. |
| v2 client in tests | 47 files in `integration-tests/aws-sdk/` (`.promise()`, `error.code`) | None needed: keep `aws-sdk` as a dev dependency so v2 compatibility stays tested. |

Risk: low at runtime (three call sites), medium in type churn. The one user-facing risk is
`.cognito/config.json`: `LambdaClient` and `KMSConfig` are passed to the SDK constructors as given.
The common keys (`endpoint`, `region`, `credentials`) mean the same in v3, but v2-only options
(`sslEnabled`, `httpOptions`, `maxRetries`) would need mapping or a documented break.

Gain: `aws-sdk` is 74 MB installed and the largest part of the Docker bundle; the v3 Cognito, Lambda
and KMS clients are a few MB. Types for operations newer than the frozen v2 model (21 targets
currently declare their own request/response interfaces, for example
`GetTokensFromRefreshToken`) would come from the SDK.

Recommendation: do it, in two separate changes. First swap the type imports (one mechanical
commit, no behaviour change, verified by the type check). Then move Lambda and KMS to v3 clients
with `@aws-crypto/client-node` 4.x, keeping the `LambdaClient` / `KMSConfig` keys and mapping the
v2-only ones. Keep the v2 client in the test suite. Estimated effort: about a day, most of it the
type pass.
