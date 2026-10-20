# Cognito Local

**122 SDK targets + 7 OAuth2/OIDC endpoints = 100% AWS Cognito User Pool API coverage**

`Build: passing` | `Tests: 721 passing` | `License: MIT` | `Node >= 22`

A local Amazon Cognito User Pool emulator for development and testing. Drop-in replacement for the real service -- point your SDK at `http://localhost:9229` and go.

> Fork of [jagregory/cognito-local](https://github.com/jagregory/cognito-local), upgraded from partial coverage to full API parity.

---

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
| `AuthSessionConfig.AuthSessionValidity` | number | `3` | Minutes a CUSTOM_AUTH challenge `Session` stays valid (kept in memory, lost on restart) |
| `AdminUIConfig.Enabled` | boolean | `true` | Serve the [admin UI](#admin-ui) at `/_admin` (no authentication, local development only) |
| `AdminUIConfig.CodeLogSize` | number | `100` | How many recent codes the admin UI keeps in memory |
| `LambdaClient.endpoint` | string | -- | Local Lambda endpoint (e.g. serverless-offline) |
| `LambdaClient.region` | string | `local` | Lambda region |
| `TriggerFunctions` | object | `{}` | Trigger-to-function mapping |
| `UserPoolDefaults.UsernameAttributes` | string[] | `["email"]` | Default username attributes |
| `KMSConfig.endpoint` | string | -- | Local KMS endpoint |

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
