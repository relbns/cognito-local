# Lambda and KMS client options

The emulator calls two AWS services itself: Lambda, to run triggers that are not `file:` targets,
and KMS, to encrypt the code a `CustomEmailSender` or `CustomSMSSender` trigger receives. Both clients come from the
AWS SDK for JavaScript v3 (`@aws-sdk/client-lambda`, and `@aws-crypto/client-node` 5.x for KMS).
Their options live in `.cognito/config.json`:

```json
{
  "LambdaClient": {
    "endpoint": "http://localhost:3002",
    "region": "local",
    "credentials": { "accessKeyId": "local", "secretAccessKey": "local" }
  },
  "KMSConfig": {
    "KMSKeyId": "arn:aws:kms:us-east-1:000000000000:key/...",
    "KMSKeyAlias": "alias/custom-sender",
    "endpoint": "http://localhost:4566",
    "region": "us-east-1"
  }
}
```

`KMSKeyId` and `KMSKeyAlias` select the key. Every other key in both sections is a client option.

## Supported options

| Option | Meaning |
| --- | --- |
| `region` | Region the client signs for |
| `endpoint` | Full URL of the service, for example a local Lambda runner or LocalStack |
| `credentials` | `{ accessKeyId, secretAccessKey, sessionToken? }` |
| `maxAttempts` | Total attempts per call, including the first |
| `retryMode` | `standard` or `adaptive` |
| `tls` | `false` to use plain HTTP when the endpoint has no scheme |
| `requestHandler` | `{ requestTimeout, connectionTimeout }` in milliseconds, and `throwOnRequestTimeout` (without it SDK v3 only logs a request that exceeds `requestTimeout`) |
| `customUserAgent`, `systemClockOffset`, `useFipsEndpoint`, `useDualstackEndpoint` | As in the SDK |

## Options written for AWS SDK v2

Before this fork moved to SDK v3, both sections were passed to the v2 constructors (`new
AWS.Lambda(...)`, `new AWS.KMS(...)`). A config written then keeps working: the v2 names that have
a v3 equivalent are translated, and the server logs one warning per key at startup.

| v2 option | Read as |
| --- | --- |
| `accessKeyId`, `secretAccessKey`, `sessionToken` at the top level | `credentials` (they win over `credentials`, as in v2) |
| `maxRetries: n` | `maxAttempts: n + 1` |
| `sslEnabled` | `tls` |
| `httpOptions.timeout` | `requestHandler.requestTimeout` with `throwOnRequestTimeout: true`, so a slow call still fails as it did in v2 |
| `httpOptions.connectTimeout` | `requestHandler.connectionTimeout` |
| `endpoint` without a scheme (`localhost:3002`) | `https://localhost:3002`, or `http://` when `sslEnabled` / `tls` is `false` |
| `endpoint` as an object | its `href` |

When a section sets both names (`maxRetries` and `maxAttempts`), the v3 one is used and the v2 one
is reported as ignored.

Every other key is ignored with a warning that names it, for example `apiVersion`,
`signatureVersion`, `logger`, `paramValidation`, `correctClockSkew`, `httpOptions.agent`,
`httpOptions.proxy` and any `requestHandler` key other than the three above. Nothing is dropped
silently. To silence the warnings, rename the keys to the v3 names above.

## Trigger events

`callerContext.awsSdkVersion` in trigger events is now `aws-sdk-unknown-unknown`, the value Cognito
sends. It used to be the version of the bundled `aws-sdk` package (for example `2.1145.0`).
