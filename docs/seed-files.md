# Seed files

A seed file declares user pools and everything in them. cognito-local applies it at startup
(`--seed <file>` or `COGNITO_LOCAL_SEED`) or on demand (`cognito-local seed <file>`, or
`POST /_admin/api/seed`). Field names are the AWS API's, so a pool reads like a `CreateUserPool`
request and a client like a `CreateUserPoolClient` request.

Examples: [`seed.basic.json`](../examples/seed.basic.json),
[`seed.custom-auth-otp.json`](../examples/seed.custom-auth-otp.json),
[`seed.federation.json`](../examples/seed.federation.json). Seed files are JSON.

## Format

```jsonc
{
  "Version": 1,
  "UserPools": [
    {
      "Id": "local_Example1",              // optional: pin the pool id
      "PoolName": "example",               // required
      // any CreateUserPool setting: Policies, Schema, UsernameAttributes, AliasAttributes,
      // AutoVerifiedAttributes, MfaConfiguration, LambdaConfig, AdminCreateUserConfig,
      // UsernameConfiguration, AccountRecoverySetting, VerificationMessageTemplate, ...
      "LambdaConfig": { "PreSignUp": "file:./triggers/pre-sign-up.js" },
      "IdentityProviders": [{ "ProviderName": "Google", "ProviderType": "Google",
                              "ProviderDetails": {}, "AttributeMapping": {} }],
      "ResourceServers": [{ "Identifier": "https://api.example.test", "Name": "API",
                            "Scopes": [{ "ScopeName": "read", "ScopeDescription": "Read" }] }],
      "Clients": [{
        "ClientId": "examplewebclient0000000001", // optional: pin the client id
        "ClientName": "web",                      // required
        "ClientSecret": "…",                      // optional: pin a secret, or "GenerateSecret": true
        // any CreateUserPoolClient setting: ExplicitAuthFlows, AllowedOAuthFlows,
        // AllowedOAuthScopes, CallbackURLs, LogoutURLs, SupportedIdentityProviders, ...
      }],
      "Groups": [{ "GroupName": "admins", "Description": "…", "Precedence": 1 }],
      "Users": [{
        "Username": "admin@example.test",         // required
        "UserAttributes": [{ "Name": "email_verified", "Value": "true" }],
        "Password": "…",                          // or "TemporaryPassword": "…"
        "UserStatus": "CONFIRMED",                // optional override
        "Enabled": true,
        "Groups": ["admins"]                      // the user's full membership
      }]
    }
  ]
}
```

Keys that start with `$` (such as `$comment`) are ignored anywhere.

## How it is applied

Applying is idempotent: what is missing is created, what differs is updated, nothing is
duplicated, and a second apply reports every entity as `unchanged`.

| Entity | Matched by | Updated on re-apply |
|--------|------------|---------------------|
| User pool | `Id`, else `PoolName` (two pools with the same name and no `Id` is an error) | every setting present in the seed |
| Identity provider | `ProviderName` | type, details, mapping, identifiers |
| Resource server | `Identifier` | name, scopes |
| App client | `ClientId`, else `ClientName` within the pool | every setting present in the seed; `ClientSecret` when pinned |
| Group | `GroupName` | description, precedence, role |
| User | `Username` (an email or phone alias works in an alias pool) | attributes listed in the seed, `Enabled`, `Groups` |

- **Pinned ids** keep tokens and app configuration stable across resets: a pinned pool `Id`,
  `ClientId` and `ClientSecret` are used as given. Pinning the `sub` attribute of a user keeps the
  `sub` claim (and, in an email or phone username pool, the internal username) stable too.
- **Users** are created through the same code as `AdminCreateUser` (with messages suppressed, no
  trigger runs), so username rules, alias uniqueness and the password policy apply. `Password`
  makes the user `CONFIRMED`; `TemporaryPassword` makes it `FORCE_CHANGE_PASSWORD`; with neither
  the user is `CONFIRMED` with a random password, which suits passwordless (CUSTOM_AUTH) pools.
  `UserStatus` overrides the status (`CONFIRMED`, `UNCONFIRMED`, `FORCE_CHANGE_PASSWORD`,
  `RESET_REQUIRED`, `EXTERNAL_PROVIDER`). A federated user (`Google_123…`, `EXTERNAL_PROVIDER`) is
  written as is.
- **Passwords and status are applied only when the user is created**, so a password changed while
  testing survives a restart that re-applies the seed. Use `cognito-local reset` for a clean start.
- A user's `sub` cannot change once created; a seed that pins a different `sub` fails with a
  message that says so.
- `Groups` on a user is its complete membership: groups not listed are left.
- Nothing is deleted: removing an entity from the seed leaves it in the data directory.
- Seeding never sends messages and never invokes triggers.

## Validation

The whole file is checked before anything is written, and every problem is reported with the file
and the field path:

```
Invalid seed /work/cognito-local.seed.json:
  - UserPools[0].MfaConfiguration: must be one of OFF, ON, OPTIONAL, got "MAYBE"
  - UserPools[0].Clients[1].ClientName: duplicate ClientName "web" (also at UserPools[0].Clients[0])
  - UserPools[0].LambdaConfig.PreSignUp: trigger file /work/triggers/pre-sign-up.js does not exist
```

Unknown fields are errors, which catches typos. Problems that depend on the stored state (a group
that does not exist, an identity provider missing from the pool, a password that breaks the
policy) stop the apply with the entity's path:

```
Cannot apply seed seed.json: UserPools[0].Users[0] (admin@example.test): InvalidPasswordException: Password does not conform to policy: Password not long enough
```

## Triggers

`LambdaConfig` takes Lambda names as in AWS, or a local module: `"file:./triggers/define.js"` or
`"file:./triggers/auth.mjs#define"`. Relative paths are resolved against the seed file's directory
and stored as absolute paths. See [local triggers](local-triggers.md).

## Export

- Admin UI: **Export as seed** on the user pools page.
- HTTP: `GET /_admin/api/export` (`?download=1` adds a `Content-Disposition` header).
- CLI: `cognito-local export [--out file]`.

The export re-creates pools, clients (with their ids and secrets), identity providers, resource
servers, groups and users (attributes including `sub`, status, enabled flag, groups). **Passwords
are not exported**, the same as Cognito; the file's `$comment` says so. Re-created users have a
random password until you add `Password` or `TemporaryPassword` to them. Exporting, applying the
export to an empty data directory and exporting again gives the same file. Links made by
`AdminLinkProviderForUser` and MFA settings are not exported.

## Admin API

| Endpoint | Body | Response |
|----------|------|----------|
| `POST /_admin/api/seed[?source=<label>&baseDir=<dir>]` | the seed (JSON) | `{ changes, summary, lines }`; 400 with `issues` or `path` when the seed is invalid or cannot be applied |
| `GET /_admin/api/export` | | the seed |
| `GET /_admin/api/status` | | `{ running, pools, issuerDomain }` |

Relative `file:` paths in a posted seed are resolved against `baseDir` (default: the server's
working directory). The CLI resolves them before posting. These endpoints exist only while the
admin UI is enabled. When an admin token is set they need `Authorization: Bearer <token>`, which
the CLI sends from `--admin-token` or `COGNITO_LOCAL_ADMIN_TOKEN`.
