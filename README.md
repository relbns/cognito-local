# cognito-local (relbns fork)

A local emulator of the Amazon Cognito User Pools API. Point an AWS SDK, the AWS CLI or a browser at
`http://localhost:9229` and sign-up, sign-in, groups, admin operations and the OAuth2 endpoints work
without an AWS account. This fork of [jagregory/cognito-local](https://github.com/jagregory/cognito-local)
adds stateful CUSTOM_AUTH (passwordless) challenges, Cognito-compatible hosted login, a mock
federated identity provider, token checks as Cognito makes them, an admin UI with a codes viewer,
seed files, local trigger files, a CLI and a Docker image. It is not AWS: it mimics the observable
behaviour closely enough for development and tests, and [the differences](#compatibility-and-differences-from-aws)
are listed below.

**Contents:** [Install](#install) | [Quick start](#quick-start) | [Recipes](#recipes) |
[Configuration](#configuration-reference) | [Compatibility](#compatibility-and-differences-from-aws) |
[Troubleshooting](#troubleshooting) | [Upstream README](#upstream-readme)

## Install

Requires **Node.js 20 or later** (`engines: >=20`). Node.js 22 is recommended: the Docker image uses
it, and the AWS SDK v3 that the emulator runs on requires 22 for releases from January 2027.

The package is not on the npm registry yet. Its name, `@relbns/cognito-local`, is reserved in
`package.json`; until it is published, install it from GitHub.

| Way | Command |
| --- | --- |
| npx, nothing installed | `npx github:relbns/cognito-local start` |
| Global command | see [Global install](#global-install) |
| Dev dependency of a project | `npm install --save-dev github:relbns/cognito-local`, then `npx cognito-local start` |
| Docker | `docker run --rm -p 127.0.0.1:9229:9229 ghcr.io/relbns/cognito-local:edge` |
| From source | `git clone`, `npm install`, `npm start` |

Every way starts the server on `http://localhost:9229` with the admin UI at `/_admin` and its data in
`./.cognito` (`/app/.cognito` in the image).

### npx

```bash
npx github:relbns/cognito-local start
```

The first run clones the repository, installs its dev dependencies and builds it (about 30 seconds).
Later runs start at once from the npx cache. Pin a version with `#<tag, branch or sha>`:
`npx github:relbns/cognito-local#1c078ef start`. If npx keeps running an older build after `main`
moved, clear its cache with `rm -rf ~/.npm/_npx`.

### Global install

`npm install -g github:relbns/cognito-local` does not work with npm 10: npm runs the package's build
step in global mode, the dev dependencies are not installed, and it fails with
`sh: tsc: command not found`. Build a tarball first and install that:

```bash
cd "$(mktemp -d)"
npm install -g "$(npm pack github:relbns/cognito-local | tail -1)"
cognito-local start
```

Remove it with `npm uninstall -g @relbns/cognito-local`.

### Docker

Multi-arch images (`linux/amd64`, `linux/arm64`) are on GitHub Container Registry. `edge` follows
`main`. `latest` and `X.Y.Z` / `X.Y` / `X` are published when a `v*` tag is pushed; no release of the
fork has been tagged yet, so use `edge`.

```bash
docker run --rm -p 127.0.0.1:9229:9229 \
  -v cognito-data:/app/.cognito \
  -v "$PWD/seed.basic.json:/seed.json:ro" \
  ghcr.io/relbns/cognito-local:edge --seed /seed.json
```

- The image runs `cognito-local start`, so arguments after the image name are `start` flags
  (`--seed`, `--no-admin`). Environment variables work too (`COGNITO_LOCAL_SEED=/seed.json`).
- It listens on `0.0.0.0:9229` inside the container as the unprivileged `node` user, keeps data and
  `config.json` in the `/app/.cognito` volume, and has a health check on `/health`.
- `-p 127.0.0.1:9229:9229` keeps the port, and the unauthenticated admin UI, off your network.
- Tokens are issued for `http://localhost:9229`. When clients reach the emulator under another name,
  set `TokenConfig.IssuerDomain` to that URL (see [Docker Compose](#docker-compose)).
- To apply a seed to a running container, run `cognito-local seed seed.json --url http://localhost:9229`
  on the host, or `curl -X POST -H 'Content-Type: application/json' --data-binary @seed.json http://localhost:9229/_admin/api/seed`.

### Docker Compose

```yaml
services:
  cognito:
    image: ghcr.io/relbns/cognito-local:edge
    command: ["--seed", "/seed/seed.json"]
    ports:
      - "127.0.0.1:9229:9229"
    volumes:
      - cognito-data:/app/.cognito
      - ./cognito/config.json:/app/.cognito/config.json
      - ./cognito/seed.json:/seed/seed.json:ro

  app:
    image: your-app
    environment:
      AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER: http://cognito:9229
      AWS_ACCESS_KEY_ID: local
      AWS_SECRET_ACCESS_KEY: local
      AWS_REGION: us-east-1
    depends_on:
      cognito:
        condition: service_healthy

volumes:
  cognito-data:
```

with `cognito/config.json`:

```json
{ "TokenConfig": { "IssuerDomain": "http://cognito:9229" } }
```

- Other containers reach the emulator as `http://cognito:9229`. The issuer is part of every token
  (`iss`) and of the OIDC discovery document, so set `IssuerDomain` to the URL the code that
  verifies tokens uses. Use `http://localhost:9229` instead when only the host and browsers talk to it.
- The emulator rewrites `config.json` when it starts, so mount it read-write; a `:ro` mount stops it
  with `EROFS: read-only file system`.
- When a seed uses `file:` triggers, mount the seed's whole directory (for example `./cognito:/seed:ro`):
  trigger paths are resolved against the seed file.

### From source

```bash
git clone https://github.com/relbns/cognito-local.git
cd cognito-local
npm install    # also builds lib/
npm start      # runs src/ with tsx; flags go after --, e.g. npm start -- --port 9330
```

`node lib/bin/cli.js start` runs the build, `npm run cli -- <command>` the TypeScript source, and
`node lib/bin/start.js` (the old entry point) is the same as `cognito-local start`.

## Quick start

The commands below use npx. With a global install write `cognito-local`; from a clone,
`node lib/bin/cli.js` and `examples/seed.basic.json`.

**1. Start with the example seed.**

```bash
curl -fsSLO https://raw.githubusercontent.com/relbns/cognito-local/main/examples/seed.basic.json
npx github:relbns/cognito-local start --seed seed.basic.json
```

[`seed.basic.json`](examples/seed.basic.json) creates the pool `local_Example1` (email as username,
a password policy, a custom attribute), a public client `examplewebclient0000000001` (password
sign-in and hosted login), a confidential client `examplebackendclient000001` (with a secret), the
groups `admins` and `members`, and three users: `admin@example.test` with password `Passw0rdAdmin`,
`jane@example.test` with a temporary password, and the unconfirmed `pending@example.test`.

**2. Open the admin UI** at <http://localhost:9229/_admin>: pools, clients, users, groups, codes and a
token decoder. It has no authentication; keep it on your machine.

![Users](docs/images/admin-users.png)

**3. Point your tools at it.** In another terminal:

```bash
export AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER=http://localhost:9229
export AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
```

The AWS SDK for JavaScript v3, boto3 and the AWS CLI v2 read the endpoint from
`AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER`, so application code needs no change. Credentials and
region must be set but are not checked. boto3 reads `AWS_DEFAULT_REGION`, not `AWS_REGION`.

**4. Sign up, confirm with the code, sign in** (AWS CLI and `jq`):

```bash
aws cognito-idp sign-up --client-id examplewebclient0000000001 \
  --username new@example.test --password 'Passw0rdNew' \
  --user-attributes Name=email,Value=new@example.test
```

The confirmation code is not emailed; it is on the **Codes** page (<http://localhost:9229/_admin/codes>),
in the server log, and in the codes feed:

```bash
CODE=$(curl -s 'http://localhost:9229/_admin/api/codes?q=new@example.test&type=SIGN_UP&limit=1' | jq -r '.codes[0].code')
aws cognito-idp confirm-sign-up --client-id examplewebclient0000000001 \
  --username new@example.test --confirmation-code "$CODE"
aws cognito-idp initiate-auth --client-id examplewebclient0000000001 \
  --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME=new@example.test,PASSWORD='Passw0rdNew'
```

![Codes](docs/images/admin-codes.png)

**5. The same from code.** JavaScript (AWS SDK v3, `npm install @aws-sdk/client-cognito-identity-provider`):

```js
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
} from "@aws-sdk/client-cognito-identity-provider";

const client = new CognitoIdentityProviderClient({});
const { AuthenticationResult } = await client.send(
  new InitiateAuthCommand({
    ClientId: "examplewebclient0000000001",
    AuthFlow: "USER_PASSWORD_AUTH",
    AuthParameters: { USERNAME: "admin@example.test", PASSWORD: "Passw0rdAdmin" },
  }),
);
console.log(AuthenticationResult.ExpiresIn);
```

Python (boto3):

```python
import boto3

cognito = boto3.client("cognito-idp")
result = cognito.initiate_auth(
    ClientId="examplewebclient0000000001",
    AuthFlow="USER_PASSWORD_AUTH",
    AuthParameters={"USERNAME": "admin@example.test", "PASSWORD": "Passw0rdAdmin"},
)
print(result["AuthenticationResult"]["ExpiresIn"])
```

To pass the endpoint in code instead: `endpoint: "http://localhost:9229"` (JavaScript v3),
`endpoint_url="http://localhost:9229"` (boto3), `--endpoint-url http://localhost:9229` (AWS CLI).
Other SDKs: [docs/sdk-compatibility.md](docs/sdk-compatibility.md).

## Recipes

### Passwordless one-time code (CUSTOM_AUTH)

[`seed.custom-auth-otp.json`](examples/seed.custom-auth-otp.json) wires `DefineAuthChallenge`,
`CreateAuthChallenge` and `VerifyAuthChallengeResponse` to the JavaScript files in
[`examples/triggers/`](examples/triggers). They run in-process with the event Lambda would get, so a
trigger written for AWS runs unchanged. From a clone:

```bash
node lib/bin/cli.js start --seed examples/seed.custom-auth-otp.json
```

```bash
SESSION=$(aws cognito-idp initiate-auth --client-id otpexampleclient0000000001 \
  --auth-flow CUSTOM_AUTH --auth-parameters USERNAME=alice@example.test \
  --query Session --output text)
CODE=$(curl -s 'http://localhost:9229/_admin/api/codes?q=alice@example.test&type=CUSTOM_AUTH&limit=1' | jq -r '.codes[0].code')
aws cognito-idp respond-to-auth-challenge --client-id otpexampleclient0000000001 \
  --challenge-name CUSTOM_CHALLENGE --session "$SESSION" \
  --challenge-responses USERNAME=alice@example.test,ANSWER="$CODE"
```

The codes viewer shows the code your `CreateAuthChallenge` returned in `privateChallengeParameters`,
and the open session with its expiry. A wrong answer returns a new `Session`, and the session expires
after the client's `AuthSessionValidity` (3 minutes by default). Wiring, module formats, errors,
timeouts and hot reload: [docs/local-triggers.md](docs/local-triggers.md).

### Hosted login and OAuth with `/_admin/callback`

`/oauth2/authorize`, `/oauth2/token`, `/oauth2/userInfo`, `/oauth2/revoke` and `/logout` follow the
Cognito contract (code and implicit grants, PKCE, scopes, client secret by Basic auth or body). To try
them without writing a client, add `http://localhost:9229/_admin/callback` to the client's
`CallbackURLs` (`seed.basic.json` already does), open <http://localhost:9229/_admin/callback>, build
the authorize URL, sign in as `admin@example.test`, and exchange the code. The page shows the token
response and the decoded tokens checked against the pool's JWKS. See
[docs/oauth-callback.md](docs/oauth-callback.md).

![Hosted login](docs/images/hosted-login.png)

### Federated sign-in with the mock IdP

Sign-in through Google, Facebook, Apple, Amazon, OIDC or SAML providers is emulated by a mock IdP
page: `identity_provider=<name>` on `/oauth2/authorize` redirects to a form where you type the
federated subject and claims. `AttributeMapping`, `EXTERNAL_PROVIDER` users (`Google_<sub>`), linked
users, the `identities` claim and the triggers then behave as in Cognito.
[`seed.federation.json`](examples/seed.federation.json) has a Google and a generic OIDC provider; start
it and use `/_admin/callback` with identity provider `Google`. See [docs/federation.md](docs/federation.md).

### Seed files and export

A seed file declares pools, clients (with pinned ids and secrets), identity providers, resource
servers, groups and users with AWS API field names. It is validated before anything is written,
applied idempotently, and never sends messages or runs triggers.

```bash
cognito-local start --seed cognito.seed.json      # at startup (or COGNITO_LOCAL_SEED)
cognito-local seed cognito.seed.json              # into the running server, or the data directory
cognito-local export --out cognito.seed.json      # current state as a seed (no passwords)
```

The admin UI has **Export as seed** on the pools page, and `GET /_admin/api/export` returns the same
file. Format and rules: [docs/seed-files.md](docs/seed-files.md).

### Persistence and reset

- Pools, clients, users, groups and token revocations are JSON files in `<data>/db/` (one per pool,
  plus `clients.json`), so they survive a restart. `config.json` sits next to `db/`.
- CUSTOM_AUTH sessions, pending OAuth logins and the codes log are in memory and are lost on restart.
- `--data <dir>` (or `COGNITO_LOCAL_DATA_DIR`) picks another directory, for example one per test run.
- `cognito-local reset --yes` deletes `<data>/db`; `--all` also deletes `config.json`. It refuses
  while a server runs on that directory, so stop the server first. In Docker, remove the volume:
  `docker volume rm cognito-data`.
- Re-applying a seed does not reset passwords or statuses changed while testing; reset for a clean
  start.

### Running in CI

Start in the background, wait until `status` succeeds, seed, run the tests, stop:

```bash
npm install --save-dev github:relbns/cognito-local   # once, in your project

npx cognito-local start --data .cognito-ci > cognito-local.log 2>&1 &
for i in $(seq 1 30); do npx cognito-local status --data .cognito-ci --json > /dev/null && break; sleep 1; done
npx cognito-local status --data .cognito-ci          # exit 3 fails the job if it never came up
npx cognito-local seed test/cognito.seed.json --data .cognito-ci

AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER=http://localhost:9229 npm test

kill "$(jq -r .pid .cognito-ci/server.json)"
```

- Tests can read codes from `GET /_admin/api/codes` (filters `pool`, `type`, `q`, `limit`), or set
  `CODE=123456` to make every confirmation, forgot-password and MFA code fixed.
- With Docker: `docker run -d --name cognito -p 9229:9229 ghcr.io/relbns/cognito-local:edge`, then
  `until curl -sf http://localhost:9229/health; do sleep 1; done`, then seed through `--url` or the
  admin API. Mount a `config.json` with `IssuerDomain` if the tests reach it under another name than `localhost`.
- `status`, `seed`, `export` and `reset` print JSON with `--json`, and the exit codes are fixed:
  0 ok, 1 error, 2 usage error or confirmation needed, 3 not running. See [docs/cli.md](docs/cli.md).

## Configuration reference

### CLI

```
cognito-local [start] [--port <n>] [--host <h>] [--data <dir>] [--seed <file>] [--admin | --no-admin]
cognito-local seed <file> [--data <dir>] [--url <url>] [--json]
cognito-local export [--out <file>] [--data <dir>] [--url <url>] [--json]
cognito-local reset [--yes] [--all] [--data <dir>] [--json]
cognito-local status [--data <dir>] [--url <url>] [--json]
cognito-local help [command] | --help | --version
```

A flag wins over the environment, the environment over the default. Details:
[docs/cli.md](docs/cli.md).

### Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `9229` | Listen port (`--port`) |
| `HOST` | `localhost` | Listen host (`--host`); `0.0.0.0` in the image |
| `COGNITO_LOCAL_DATA_DIR` | `.cognito` | Data directory (`--data`) |
| `COGNITO_LOCAL_SEED` | none | Seed file applied at startup (`--seed`) |
| `COGNITO_LOCAL_ADMIN_UI` | on | `false`, `0` or `off` disables the admin UI and its API (`--no-admin`) |
| `CODE` | random | Fixed code for confirmation, forgot-password, MFA and temporary passwords |
| `SMTP_HOST`, `SMTP_PORT` | unset, `1025` | Send emails to an SMTP server (for example a local mail catcher) instead of logging them |
| `DEBUG` | unset | Verbose logging |
| `COGNITO_LOCAL_DEVMODE` | unset (`1` in `npm start`) | Log the request body of unsupported operations |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` | | Accept self-signed certificates from a Lambda endpoint |

### `config.json`

`<data>/config.json` is optional. Keys added or changed by this fork (the upstream keys are in the
[upstream configuration table](#configuration)):

| Key | Default | Meaning |
| --- | --- | --- |
| `TokenConfig.IssuerDomain` | `http://<host>:<port>` | Base of the `iss` claim and of the OIDC discovery URLs. Set it when clients reach the emulator under another name |
| `TokenConfig.Verify` | `true` | Verify access and refresh tokens as Cognito does; `false` decodes access tokens unchecked: see [docs/tokens.md](docs/tokens.md) |
| `TokenConfig.CheckSecretHash` | `true` | Require `SECRET_HASH` / `SecretHash` / `ClientSecret` from clients with a secret |
| `PasswordPolicyConfig.Enforce` | `true` | Enforce each pool's `PasswordPolicy` (the AWS default when unset) |
| `AuthSessionConfig.AuthSessionValidity` | `3` | Minutes a CUSTOM_AUTH `Session` stays valid when the client sets no `AuthSessionValidity` |
| `AdminUIConfig.Enabled` | `true` | Serve the admin UI at `/_admin` and record codes |
| `AdminUIConfig.CodeLogSize` | `100` | How many recent codes the admin UI keeps |
| `FileTriggerConfig.TimeoutMs` | `5000` | How long a `file:` trigger may run |
| `FileTriggerConfig.HotReload` | `true` | Reload a `file:` trigger when the file changes |
| `TriggerFunctions` | `{}` | Triggers for every pool: Lambda names, or `file:` paths resolved against the data directory |
| `UserPoolDefaults.UsernameAttributes` | `["email"]` | Pools created without `UsernameAttributes` use email as the username; `[]` gives free-form usernames as in Cognito |
| `LambdaClient`, `KMSConfig` | local credentials | AWS SDK v3 client options; v2 names are translated with a warning: see [docs/aws-client-config.md](docs/aws-client-config.md) |

### Detailed docs

| Topic | Doc |
| --- | --- |
| Commands, flags, data directory, exit codes | [docs/cli.md](docs/cli.md) |
| Seed file format, apply rules, export | [docs/seed-files.md](docs/seed-files.md) |
| `file:` triggers | [docs/local-triggers.md](docs/local-triggers.md) |
| OAuth callback page | [docs/oauth-callback.md](docs/oauth-callback.md) |
| Mock federated IdP | [docs/federation.md](docs/federation.md) |
| Token checks, revocation, validity, `SECRET_HASH` | [docs/tokens.md](docs/tokens.md) |
| Tested SDKs and known gaps | [docs/sdk-compatibility.md](docs/sdk-compatibility.md) |
| Lambda and KMS client options | [docs/aws-client-config.md](docs/aws-client-config.md) |

## Compatibility and differences from AWS

Tested with the AWS SDK for JavaScript v2 and v3, boto3 and the AWS CLI v2; see
[docs/sdk-compatibility.md](docs/sdk-compatibility.md) for versions and per-SDK settings. SigV4
signatures are not checked, so any credentials and region work.

Not supported yet:

- Federated providers are a mock page, with no real OIDC token exchange or SAML assertion.
- The `client_credentials` grant on `/oauth2/token` (only `authorization_code` and `refresh_token`).
- The `USER_AUTH` (choice-based) flow. SRP proofs are not verified: `USER_SRP_AUTH` checks the password directly.
- Refresh token rotation, and the PreAuthentication trigger.
- Request parameters are not validated against the API model, so a missing parameter may give a
  different error than `InvalidParameterException`.
- The built-in login page is a plain form without Cognito's styling.
- The admin UI has no authentication.

Stricter than upstream cognito-local, and the switch that restores the lenient behaviour:

| Behaviour | Switch in `config.json` |
| --- | --- |
| Access and refresh tokens verified (signature, issuer, expiry, user, revocation) | `TokenConfig.Verify: false` |
| `SECRET_HASH` required from clients with a secret | `TokenConfig.CheckSecretHash: false` |
| Pool `PasswordPolicy` enforced | `PasswordPolicyConfig.Enforce: false` |
| Admin UI on, codes recorded | `AdminUIConfig.Enabled: false` or `--no-admin` |

One difference goes the other way: pools default to email as the username
(`UserPoolDefaults.UsernameAttributes: ["email"]`), where Cognito defaults to free-form usernames.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `listen EADDRINUSE: address already in use ::1:9229` | Another process holds the port. 9229 is also Node's default `--inspect` port, so a debugger can hold it. Use `--port 9330`, or find it with `lsof -iTCP:9229 -sTCP:LISTEN`. |
| `cognito-local is already serving .cognito at ...; stop it first.` | A server already runs on this data directory. Stop it, or use another `--data`. |
| `curl http://127.0.0.1:9229` is refused while `localhost` works | The default host `localhost` can bind IPv6 `::1` only. Use `localhost` in URLs, or start with `--host 127.0.0.1`. |
| A container cannot reach an emulator running on the host | It listens on `localhost` only. Start it with `--host 0.0.0.0` and set `TokenConfig.IssuerDomain`, or run the Docker image on the same network. |
| Token verification fails with an issuer or JWKS mismatch | `iss` is `TokenConfig.IssuerDomain` + `/<poolId>`, by default the emulator's own host and port. When clients reach it under another name (a Compose service name, a mapped port), set `IssuerDomain` to that URL and fetch the JWKS from `<IssuerDomain>/<poolId>/.well-known/jwks.json`. |
| boto3: `NoRegionError: You must specify a region` | boto3 ignores `AWS_REGION`. Set `AWS_DEFAULT_REGION` or pass `region_name`. |
| AWS SDK v2: `LambdaConfig` value rejected as too short | SDK v2 checks a 20-character minimum on `LambdaConfig` values. Use an absolute path: `file:/abs/path/triggers/define.js`. |
| `NodeVersionSupportWarning: ... will require node >=22` | Printed by the AWS SDK on Node 20. Harmless; Node 22 removes it. Node below 20 is not supported. |
| `npm install -g github:relbns/cognito-local` fails with `tsc: command not found` | npm builds git dependencies in global mode without dev dependencies. Use the [tarball install](#global-install). |
| `EROFS: read-only file system, open '.cognito/config.json'` | `config.json` is mounted read-only; the emulator rewrites it at startup. Mount it read-write. |
| `InvalidParameterException: Username should be an email.` | Pools default to email as the username. Set `UsernameAttributes: []` on the pool or in `UserPoolDefaults`. |
| The admin UI is reachable from other machines | It has no authentication and shows codes and client secrets. Bind to `localhost` (the CLI default), publish Docker ports as `127.0.0.1:9229:9229`, or turn it off with `--no-admin`. |

## Screenshots

<details>
<summary>Admin UI pages</summary>

User pools, and a pool with its settings and app clients:

![User pools](docs/images/admin-pools.png)
![Pool detail](docs/images/admin-pool-detail.png)

One user with attributes, groups and actions:

![User detail](docs/images/admin-user-detail.png)

Tokens: a decoded ID token, verified against the pool JWKS:

![Tokens](docs/images/admin-tokens.png)

</details>

## Credits

Upstream: [jagregory/cognito-local](https://github.com/jagregory/cognito-local) by James Gregory and
contributors. Full API coverage and the OAuth2/OIDC endpoints:
[PR #468](https://github.com/jagregory/cognito-local/pull/468) by [vipinkashyap](https://github.com/vipinkashyap),
integrated here on top of upstream 5.3.0. MIT licensed, like upstream.

---

<!-- Everything below this line is the upstream README. -->

# Upstream README

> Everything below is the README from PR #468 (vipinkashyap's rewrite of the upstream README), kept as it was apart from its title level. The fork's additions to it are the `/oauth2/authorize` and `/oauth2/token` rows, the Admin UI section and the `AuthSessionConfig` / `AdminUIConfig` / `COGNITO_LOCAL_ADMIN_UI` configuration rows.

## Cognito Local

**122 SDK targets + 7 OAuth2/OIDC endpoints = 100% AWS Cognito User Pool API coverage**

`Build: passing` | `Tests: 721 passing` | `License: MIT` | `Node >= 22`

A local Amazon Cognito User Pool emulator for development and testing. Drop-in replacement for the real service -- point your SDK at `http://localhost:9229` and go.

> Fork of [jagregory/cognito-local](https://github.com/jagregory/cognito-local), upgraded from partial coverage to full API parity.


## Quick Start

### npm

```bash
npm start
# Listening on http://localhost:9229
```

### Docker

```bash
docker compose up
# Listening on http://localhost:9229
```

### Point your SDK at it

```js
const client = new CognitoIdentityProviderClient({
  region: "us-east-1",
  endpoint: "http://localhost:9229",
});
```

### Create a User Pool

```bash
aws --endpoint http://localhost:9229 cognito-idp create-user-pool --pool-name MyPool
```

> Credentials are required by the CLI but not validated. Use dummy values if needed:
> `AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local aws --endpoint http://localhost:9229 cognito-idp ...`

---

## What's Supported

### Authentication

| Category | Targets |
|----------|---------|
| Auth flows | InitiateAuth, AdminInitiateAuth, RespondToAuthChallenge, AdminRespondToAuthChallenge |
| SRP auth | USER_SRP_AUTH, PASSWORD_VERIFIER (simplified -- verifies password directly) |
| Password auth | USER_PASSWORD_AUTH |
| Custom auth | CUSTOM_AUTH with DefineAuthChallenge, CreateAuthChallenge, VerifyAuthChallengeResponse triggers; multi-round sessions with challenge history, retries after a wrong answer, SRP_A + PASSWORD_VERIFIER before the custom challenge |
| Refresh tokens | GetTokensFromRefreshToken, REFRESH_TOKEN / REFRESH_TOKEN_AUTH |
| Sign-up | SignUp, ConfirmSignUp, ResendConfirmationCode |
| Password reset | ForgotPassword, ConfirmForgotPassword, AdminResetUserPassword |
| Sign-out | GlobalSignOut, AdminUserGlobalSignOut, RevokeToken |

**Challenge types:** SMS_MFA, SOFTWARE_TOKEN_MFA, NEW_PASSWORD_REQUIRED, PASSWORD_VERIFIER, MFA_SETUP, CUSTOM_CHALLENGE

### MFA

| Target | Description |
|--------|-------------|
| AssociateSoftwareToken | Begin TOTP setup, returns secret |
| VerifySoftwareToken | Verify TOTP code |
| SetUserMFAPreference | Set per-user MFA preference |
| AdminSetUserMFAPreference | Admin variant |
| SetUserPoolMfaConfig | Pool-level MFA config |
| GetUserPoolMfaConfig | Read pool-level MFA config |
| GetUserAuthFactors | List user's auth factors |

### User CRUD

AdminCreateUser, AdminGetUser, AdminDeleteUser, AdminEnableUser, AdminDisableUser, AdminSetUserPassword, AdminUpdateUserAttributes, AdminDeleteUserAttributes, AdminConfirmSignUp, GetUser, DeleteUser, ChangePassword, UpdateUserAttributes, DeleteUserAttributes, GetUserAttributeVerificationCode, VerifyUserAttribute, AdminSetUserSettings, SetUserSettings

### Groups

CreateGroup, GetGroup, UpdateGroup, DeleteGroup, ListGroups, AdminAddUserToGroup, AdminRemoveUserFromGroup, AdminListGroupsForUser, ListUsersInGroup

### User Pools & Clients

CreateUserPool, DescribeUserPool, UpdateUserPool, DeleteUserPool, ListUserPools, CreateUserPoolClient, DescribeUserPoolClient, UpdateUserPoolClient, DeleteUserPoolClient, ListUserPoolClients, AddCustomAttributes, AddUserPoolClientSecret, DeleteUserPoolClientSecret, ListUserPoolClientSecrets

### Identity Providers (Federation)

CreateIdentityProvider, DescribeIdentityProvider, UpdateIdentityProvider, DeleteIdentityProvider, ListIdentityProviders, GetIdentityProviderByIdentifier, AdminLinkProviderForUser, AdminDisableProviderForUser

### Resource Servers

CreateResourceServer, DescribeResourceServer, UpdateResourceServer, DeleteResourceServer, ListResourceServers

### Devices

ConfirmDevice, GetDevice, AdminGetDevice, ForgetDevice, AdminForgetDevice, UpdateDeviceStatus, AdminUpdateDeviceStatus, ListDevices, AdminListDevices

### Domains & Branding

CreateUserPoolDomain, DescribeUserPoolDomain, UpdateUserPoolDomain, DeleteUserPoolDomain, CreateManagedLoginBranding, DescribeManagedLoginBranding, DescribeManagedLoginBrandingByClient, UpdateManagedLoginBranding, DeleteManagedLoginBranding, GetUICustomization, SetUICustomization

### WebAuthn (Passkeys)

StartWebAuthnRegistration, CompleteWebAuthnRegistration, ListWebAuthnCredentials, DeleteWebAuthnCredential

### Import Jobs

CreateUserImportJob, DescribeUserImportJob, StartUserImportJob, StopUserImportJob, ListUserImportJobs, GetCSVHeader

### Tags, Terms, Risk, Logging

TagResource, UntagResource, ListTagsForResource, CreateTerms, DescribeTerms, UpdateTerms, DeleteTerms, ListTerms, DescribeRiskConfiguration, SetRiskConfiguration, GetLogDeliveryConfiguration, SetLogDeliveryConfiguration

### Other

AdminListUserAuthEvents, AdminUpdateAuthEventFeedback, UpdateAuthEventFeedback, GetSigningCertificate

### Pagination

All `List*` APIs support pagination via `NextToken` / `MaxResults`.

---

## OAuth2 / OIDC Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth2/authorize` | GET, POST | Authorization endpoint: `code` and `token` response types (any case), optional PKCE (S256), scopes checked against `AllowedOAuthScopes`, errors redirected to `redirect_uri`. `identity_provider=COGNITO` shows the built-in login; a federated IdP returns 501 (not implemented yet) |
| `/oauth2/token` | POST | Token exchange (authorization_code, refresh_token). Clients with a secret authenticate with HTTP Basic or `client_secret` in the body |
| `/oauth2/userInfo` | GET | OpenID Connect UserInfo |
| `/oauth2/revoke` | POST | Token revocation |
| `/logout` | GET | End session / logout |
| `/{poolId}/.well-known/jwks.json` | GET | JSON Web Key Set |
| `/{poolId}/.well-known/openid-configuration` | GET | OIDC discovery document |

---

## Admin UI

A web UI served by the emulator itself at **`http://localhost:9229/_admin`**, in the spirit of `dynamodb-admin`.

> **Warning:** the admin UI has **no authentication**. Anyone who can reach the port can read every user, code and client secret, and change users. It is for local development only. Turn it off (see below) whenever the emulator is reachable from a shared network.

- **User pools**: every pool with its settings summary, and its app clients with their auth flows and OAuth settings (flows, scopes, callback and logout URLs).
- **Users**: search by username, email, phone or `sub`, filter by status; view attributes, status, groups and the codes pending on the user. Create a user (optionally with a permanent password and verified email/phone), delete, confirm (`AdminConfirmSignUp`), set a password, enable/disable, add to or remove from a group. Every action runs through the same target the API uses (`AdminCreateUser`, `AdminSetUserPassword`, ...), so triggers and validation behave as they do for an SDK call.
- **Groups**: each pool's groups with their members; create a group.
- **Codes**: the codes the emulator produced since it started, newest first: sign-up confirmation, forgot-password, SMS MFA, temporary passwords, attribute verification, and every `CUSTOM_AUTH` round with the `privateChallengeParameters` your `CreateAuthChallenge` trigger returned (an OTP in `secretLoginCode` is shown as the code). Active `CUSTOM_AUTH` sessions are listed with a live expiry countdown. Kept in memory only (last `AdminUIConfig.CodeLogSize`), lost on restart.
- **Tokens**: paste a JWT to decode its header and claims and verify it against the pool's JWKS (key id, signature, issuer, expiry, client/audience).

For test scripts, the codes feed is also available as JSON:

```bash
curl -s 'http://localhost:9229/_admin/api/codes?q=jane@example.com&type=CUSTOM_AUTH&limit=1'
# { "codes": [{ "type": "CUSTOM_AUTH", "code": "123456", "username": "...", ... }], "sessions": [...] }
```

Filters: `pool` (user pool id), `type` (`SIGN_UP`, `FORGOT_PASSWORD`, `MFA`, `TEMPORARY_PASSWORD`, `ATTRIBUTE_VERIFICATION`, `CUSTOM_AUTH`), `q` (substring of username, email, phone or code) and `limit`.

**Enable / disable**: on by default. Disable with `"AdminUIConfig": { "Enabled": false }` in `.cognito/config.json` or the environment variable `COGNITO_LOCAL_ADMIN_UI=false`; when disabled, `/_admin` is not mounted and no codes are recorded.

---

## Configuration

Configuration lives in `.cognito/config.json`. Create it only if you need to customize behavior:

```bash
mkdir -p .cognito && echo '{}' > .cognito/config.json
```

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `ServerConfig.hostname` | string | `localhost` | Hostname to bind |
| `ServerConfig.port` | number | `9229` | Port to listen on |
| `ServerConfig.https` | boolean | `false` | Enable TLS |
| `ServerConfig.cert` | string | -- | Path to TLS cert |
| `ServerConfig.key` | string | -- | Path to TLS key |
| `TokenConfig.IssuerDomain` | string | `http://localhost:9229` | JWT issuer domain |
| `AuthSessionConfig.AuthSessionValidity` | number | `3` | Minutes a CUSTOM_AUTH challenge `Session` stays valid when the app client sets no `AuthSessionValidity` (kept in memory, lost on restart) |
| `AdminUIConfig.Enabled` | boolean | `true` | Serve the [admin UI](#admin-ui) at `/_admin` (no authentication, local development only) |
| `AdminUIConfig.CodeLogSize` | number | `100` | How many recent codes the admin UI keeps in memory |
| `LambdaClient.endpoint` | string | -- | Local Lambda endpoint (e.g. serverless-offline); the section takes AWS SDK v3 client options, see [docs/aws-client-config.md](docs/aws-client-config.md) |
| `LambdaClient.region` | string | `local` | Lambda region |
| `TriggerFunctions` | object | `{}` | Trigger-to-function mapping |
| `UserPoolDefaults.UsernameAttributes` | string[] | `["email"]` | Default username attributes |
| `KMSConfig.endpoint` | string | -- | Local KMS endpoint (AWS SDK v3 client options, like `LambdaClient`) |

### Lambda Triggers

Configure triggers by mapping trigger names to Lambda function names:

```json
{
  "LambdaClient": {
    "endpoint": "http://localhost:3002"
  },
  "TriggerFunctions": {
    "PreSignUp": "my-presignup-fn",
    "PostConfirmation": "my-postconfirm-fn",
    "CustomMessage": "my-custom-message-fn",
    "DefineAuthChallenge": "my-define-auth-fn",
    "CreateAuthChallenge": "my-create-auth-fn",
    "VerifyAuthChallengeResponse": "my-verify-auth-fn"
  }
}
```

Supported triggers: PreSignUp, PostConfirmation, PostAuthentication, PreAuthentication, PreTokenGeneration, CustomMessage, CustomEmailSender, UserMigration, DefineAuthChallenge, CreateAuthChallenge, VerifyAuthChallengeResponse.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `PORT` | Override listen port |
| `HOST` | Override listen hostname |
| `DEBUG` | Enable verbose logging |
| `CODE` | Fixed confirmation code (instead of random) |
| `COGNITO_LOCAL_ADMIN_UI` | `false`, `0` or `off` disables the admin UI |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` | Accept self-signed certs for Lambda endpoints |

### Data Storage

User Pools are stored as JSON files in `.cognito/db/`. Clients are stored in `.cognito/db/clients.json`. Mount this directory as a volume in Docker to persist data between runs.

---

## API Parity Summary

| Category | Targets | Status |
|----------|--------:|--------|
| Authentication & sign-up | 14 | All implemented |
| MFA (TOTP) | 7 | All implemented |
| User CRUD (admin + self-service) | 18 | All implemented |
| Groups | 9 | All implemented |
| User pools & clients | 14 | All implemented |
| Identity providers | 8 | All implemented |
| Resource servers | 5 | All implemented |
| Devices | 9 | All implemented |
| Domains & branding | 10 | All implemented |
| WebAuthn | 4 | All implemented |
| Import jobs | 6 | All implemented |
| Tags, terms, risk, logging | 12 | All implemented |
| Other | 4 | All implemented |
| OAuth2/OIDC endpoints | 7 | All implemented |
| **Total** | **~129** | **100%** |

---

## Tech Stack

| Component | Version |
|-----------|---------|
| Node.js | 22+ |
| TypeScript | 5.9 |
| Express | 5 |
| Test runner | Vitest |
| Linter | Biome |
| Build | esbuild |

---

## Roadmap

This project will become `@nimbus/plugin-cognito` as part of the [Nimbus](https://github.com/your-org/nimbus) local AWS emulator suite.

---

## Contributing

1. Fork the repo and create a feature branch.
2. Write tests for new targets (see existing `*.test.ts` files for patterns).
3. Run `npm test` and ensure all 721+ tests pass.
4. Submit a pull request.

---

## License

MIT
