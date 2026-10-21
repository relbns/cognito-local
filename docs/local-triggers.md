# Local triggers

A Lambda trigger can be a JavaScript file on your machine instead of a Lambda function. cognito-local
loads the module in its own process and calls the handler with the same event it would send to
Lambda, so a trigger written for AWS runs unchanged.

## Wiring

In a pool's `LambdaConfig` (seed file, `CreateUserPool` or `UpdateUserPool`):

```json
"LambdaConfig": {
  "DefineAuthChallenge": "file:./triggers/define-auth-challenge.js",
  "CreateAuthChallenge": "file:./triggers/create-auth-challenge.mjs",
  "VerifyAuthChallengeResponse": "file:./triggers/verify.js#handler",
  "CustomEmailSender": { "LambdaArn": "file:./triggers/email.js", "LambdaVersion": "V1_0" }
}
```

Or for every pool, in `<data>/config.json`:

```json
"TriggerFunctions": { "PreSignUp": "file:./triggers/pre-sign-up.js" }
```

- Syntax: `file:<path>[#<export>]`. The export defaults to `handler`. `file:///abs/path.js` works too.
- Relative paths: against the seed file's directory for seeds (stored as absolute paths), and
  against the data directory for `config.json` and for paths set through `CreateUserPool` /
  `UpdateUserPool`. The AWS SDK for JavaScript v2 checks that a `LambdaConfig` value is at least
  20 characters long, so prefer absolute paths there.
- Precedence: a pool's `file:` entry wins over `TriggerFunctions`. A pool `LambdaConfig` entry that
  is a Lambda ARN is ignored, as before; `TriggerFunctions` entries that are not `file:` keep going
  to the Lambda endpoint configured in `LambdaClient`.
- Supported triggers: the ones cognito-local invokes (`PreSignUp`, `PostConfirmation`,
  `PostAuthentication`, `DefineAuthChallenge`, `CreateAuthChallenge`, `VerifyAuthChallengeResponse`,
  `PreTokenGeneration`, `UserMigration`, `CustomMessage`, `CustomEmailSender`).

A `PreTokenGeneration` trigger receives the event version of the pool's
`PreTokenGenerationConfig.LambdaVersion`, whether it is a `file:` target or a Lambda reached through
`TriggerFunctions`:

```json
"LambdaConfig": {
  "PreTokenGenerationConfig": { "LambdaArn": "file:./triggers/pre-token.js", "LambdaVersion": "V2_0" }
}
```

A pool with only `PreTokenGeneration`, or with no `LambdaVersion`, gets version 1 events. See
[tokens.md](tokens.md#pre-token-generation) for what each version can change.

## Modules and handlers

- CommonJS (`.js` in a CommonJS package, `.cjs`) and ES modules (`.mjs`, or `.js` in a package with
  `"type": "module"`). A handler on the default export is found too.
- `async (event, context) => event`, or `(event, context, callback) => callback(null, event)`.
  `context` has `functionName`, `awsRequestId`, `getRemainingTimeInMillis()` and friends.
- Return the event with its `response` filled in, as Lambda requires. A handler that returns
  nothing fails with `InvalidLambdaResponseException`.
- The event is a JSON copy, so a handler cannot change cognito-local's state by mutating it.
- TypeScript is not compiled: point at built JavaScript.

## Errors and timeouts

| What happens | What the caller gets |
|--------------|----------------------|
| The handler throws, rejects, or calls `callback(err)` | `UserLambdaValidationException: <Trigger> failed with error <message>.` |
| It runs longer than `FileTriggerConfig.TimeoutMs` (5000, Cognito's limit) | `UnexpectedLambdaExceptionException: <Trigger> invocation failed due to error Task timed out after 5.00 seconds.` |
| The file or export cannot be loaded | `UnexpectedLambdaExceptionException` with the load error |
| It returns no `response` | `InvalidLambdaResponseException` |

## Hot reload

With `FileTriggerConfig.HotReload` (on by default) a trigger file is re-imported when its
modification time changes, so editing a trigger needs no restart. Only the file named in
`LambdaConfig` is watched: a module it imports is reloaded only when the entry file changes.

## Configuration

| Key in `config.json` | Default | Meaning |
|----------------------|---------|---------|
| `FileTriggerConfig.TimeoutMs` | `5000` | How long a file trigger may run |
| `FileTriggerConfig.HotReload` | `true` | Reload a trigger file when it changes |

## Example

[`examples/seed.custom-auth-otp.json`](../examples/seed.custom-auth-otp.json) wires a passwordless
one-time-code sign-in from three files in [`examples/triggers/`](../examples/triggers): a CommonJS
`DefineAuthChallenge`, an ES module `CreateAuthChallenge` that prints the code, and a callback-style
`VerifyAuthChallengeResponse`. The code also appears in the admin UI at `/_admin/codes`.
