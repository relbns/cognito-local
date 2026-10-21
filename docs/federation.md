# Federated identity providers

cognito-local emulates sign-in through a third-party identity provider (Google, Facebook,
LoginWithAmazon, SignInWithApple, OIDC, SAML). By default a built-in mock IdP page stands in for
the provider, without any network call. In [real mode](#real-providers) the emulator signs in
through the provider itself (OIDC and the social providers). Either way, everything after the
provider follows the Cognito contract.

## Setup

1. Create the IdP on the pool with `CreateIdentityProvider` (name, type, `ProviderDetails`,
   `AttributeMapping`, optional `IdpIdentifiers`).
2. Enable it on the app client: `SupportedIdentityProviders: ["COGNITO", "Google", ...]`, with
   `AllowedOAuthFlows`, `AllowedOAuthScopes` and `CallbackURLs` as usual.

## Flow (mock IdP)

1. `GET /oauth2/authorize?identity_provider=<name>` (or `idp_identifier=<identifier>`) with the
   usual `client_id`, `redirect_uri`, `response_type`, `scope`, `state` and optional PKCE. The
   request is kept server-side (10 minutes, single use) and the browser is redirected to
   `/mock-idp/<name>/authorize`, with the parameters Cognito would send to the real IdP.
2. The mock IdP page asks for the federated identity: the subject (`sub`, `id` for Facebook,
   `user_id` for LoginWithAmazon, `NameID` for SAML) and a table of IdP claims. The claim names
   are prefilled from the IdP's `AttributeMapping`, so the mapping picks them up. **Simulate IdP
   error** returns `access_denied` instead.
3. The form posts to `/oauth2/idpresponse`, which:
   - applies `AttributeMapping` (`<pool attribute>: <IdP claim>`); unmapped claims are dropped;
   - signs in a native user linked with `AdminLinkProviderForUser`
     (`ProviderAttributeName: Cognito_Subject`, or a claim name for OIDC/SAML), updating it with
     the mapped claims;
   - otherwise reuses or creates `<ProviderName>_<subject>` (for example `Google_1234`) with status
     `EXTERNAL_PROVIDER` and an `identities` attribute
     (`userId`, `providerName`, `providerType`, `issuer`, `primary`, `dateCreated`);
   - redirects to `redirect_uri` with `code` and `state` (or tokens in the fragment for
     `response_type=token`), exactly like the hosted login.

Mapped attributes are refreshed on every sign-in, as Cognito does.

## Real providers

Real mode is opt-in, in `<data>/config.json`. `FederationConfig.Mode` applies to every provider,
and `FederationConfig.Providers.<ProviderName>.Mode` overrides it for one provider name, in every
pool:

```json
{
  "FederationConfig": {
    "Mode": "mock",
    "Providers": {
      "CorpIdP": { "Mode": "real" }
    }
  }
}
```

| Key | Default | Meaning |
| --- | --- | --- |
| `FederationConfig.Mode` | `"mock"` | `"real"` signs in through the provider; `"mock"` shows the mock IdP page |
| `FederationConfig.Providers.<name>.Mode` | unset | `"mock"` or `"real"` for the provider with that `ProviderName` |

Any other value stops the server at startup. The identity provider itself is configured exactly as
in Cognito (`CreateIdentityProvider` or a seed file): the switch lives in `config.json` so a seed
keeps mirroring what AWS accepts. SAML providers always use the mock IdP, in either mode.

### What the emulator does

1. **Endpoints.** It reads the endpoints from `ProviderDetails`, as Cognito accepts them:

   | Type | Endpoints |
   | --- | --- |
   | `OIDC` | `authorize_url`, `token_url`, `attributes_url`, `jwks_uri`; any missing one comes from `<oidc_issuer>/.well-known/openid-configuration` (`userinfo_endpoint` for `attributes_url`) |
   | `Google` | as `OIDC`, with `oidc_issuer` `https://accounts.google.com` |
   | `SignInWithApple` | as `OIDC`, with `oidc_issuer` `https://appleid.apple.com` |
   | `Facebook` | `https://www.facebook.com/<api_version>/dialog/oauth`, `https://graph.facebook.com/<api_version>/oauth/access_token` (GET), `https://graph.facebook.com/<api_version>/me?fields=` (`api_version` defaults to `v17.0`) |
   | `LoginWithAmazon` | `https://www.amazon.com/ap/oa`, `https://api.amazon.com/auth/o2/token`, `https://api.amazon.com/user/profile` |

   A key in `ProviderDetails` (`authorize_url`, `token_url`, `attributes_url`, `jwks_uri`,
   `oidc_issuer`, `token_request_method`, `attributes_request_method`,
   `attributes_url_add_attributes`) overrides the default for every type. Discovery documents and
   JWKS are cached for 10 minutes, and the JWKS is fetched again when an `id_token` names a `kid`
   the cache does not have.
2. **Authorize.** `GET /oauth2/authorize?identity_provider=<name>` (or `idp_identifier`) redirects
   to the provider's authorize endpoint with `response_type=code`, `client_id`, `scope`
   (`authorize_scopes`), `redirect_uri` (`<emulator>/oauth2/idpresponse`, built from the request's
   host) and `state`. OIDC providers also get a `nonce`, and a PKCE `code_challenge` (`S256`) when
   the discovery document lists `S256` in `code_challenge_methods_supported`. SignInWithApple gets
   `response_mode=form_post` when the scopes include `name` or `email`. The `state`, `nonce` and PKCE
   verifier stay on the emulator (10 minutes, single use), next to the app's own request.
3. **Code exchange.** `/oauth2/idpresponse` (GET, or POST for `form_post`) checks the `state` and
   sends the code to the token endpoint with `grant_type=authorization_code`, `redirect_uri`,
   `client_id` and `client_secret` in the form body (`client_secret_post`, the only method Cognito
   uses), plus the PKCE `code_verifier`. `token_request_method: GET` puts them in the query string,
   as Facebook expects. For SignInWithApple without a `client_secret`, the client secret is an ES256
   JWT signed with `private_key`, with `kid` `key_id`, `iss` `team_id` and `sub` `client_id`.
4. **ID token** (OIDC, Google, SignInWithApple). The `id_token` must be signed with RSA, RSA-PSS,
   ECDSA (key from `jwks_uri`, matched by `kid`) or HMAC (`client_secret`); `iss` must equal
   `oidc_issuer` (Google also sends `accounts.google.com`), `aud` must be or contain `client_id`,
   `exp` must be in the future and `nonce` must be the one sent.
5. **Attributes.** With an `attributes_url`, the emulator calls it with the access token
   (`Authorization: Bearer`, method `attributes_request_method`, GET by default). With
   `attributes_url_add_attributes: "true"` (the Facebook default) it appends the mapped IdP
   attribute names, comma-separated, to the URL (Facebook also gets `id`). The response claims are
   added to the `id_token` claims, and a `sub` that differs from the `id_token` fails the sign-in.
   For SignInWithApple, the `user` form field of the first sign-in adds `firstName`, `lastName`
   and `name`.
6. **Sign-in.** The claims go through the same path as the mock IdP: `AttributeMapping`, linked
   users, `<ProviderName>_<subject>` users, `identities`, triggers, the browser session and the
   redirect to the app with a code or tokens.

### Point it at a provider

Register `http://localhost:9229/oauth2/idpresponse` (the emulator's host and port as the browser
reaches it) as a redirect URI of a client at the provider, then give the emulator that client.

A local OIDC server, such as a Keycloak realm on port 8080:

```json
{
  "ProviderName": "LocalOIDC",
  "ProviderType": "OIDC",
  "ProviderDetails": {
    "client_id": "local-app",
    "client_secret": "local-app-secret",
    "oidc_issuer": "http://localhost:8080/realms/example",
    "authorize_scopes": "openid email profile",
    "attributes_request_method": "GET"
  },
  "AttributeMapping": { "email": "email", "name": "name", "username": "sub" }
}
```

A real Google OAuth client (type "Web application", with the redirect URI above under
"Authorized redirect URIs"):

```json
{
  "ProviderName": "Google",
  "ProviderType": "Google",
  "ProviderDetails": {
    "client_id": "1example23456789.apps.googleusercontent.com",
    "client_secret": "provider-app-client-secret",
    "authorize_scopes": "openid email profile"
  },
  "AttributeMapping": { "email": "email", "email_verified": "email_verified", "username": "sub" }
}
```

Enable the provider on the app client (`SupportedIdentityProviders`), set
`"FederationConfig": { "Providers": { "Google": { "Mode": "real" } } }` and restart the emulator.
Then open `/oauth2/authorize?identity_provider=Google&...` in a browser, or use `/_admin/callback`.

### Errors in real mode

Every failure is a redirect to the app's `redirect_uri` with `error`, `error_description` and the
app's `state`, as Cognito does:

| Case | `error` | `error_description` |
| --- | --- | --- |
| The provider redirects back with an error | as returned (`access_denied`) | as returned |
| The token, userInfo or discovery endpoint answers with an HTTP error | the provider's `error`, else `invalid_request` | `<ProviderName> Error - <status> <error> <error_description>` |
| The provider cannot be reached (10 second timeout) | `server_error` | `<ProviderName> Error - could not reach <origin>: <reason>` |
| No `code` in the response | `invalid_request` | `<ProviderName> did not return an authorization code` |
| No `id_token` from an OIDC provider | `invalid_request` | `<ProviderName> returned no id_token: include openid in authorize_scopes` |
| Bad `id_token` | `invalid_request` | `Bad id_token: invalid signature`, `Bad id_token issuer <iss>`, `Bad id_token aud <aud>`, `Bad id_token: expired`, `Bad id_token nonce`, `Bad id_token: signing key <kid> is not published at the jwks_uri of <ProviderName>` |
| userInfo `sub` differs from the `id_token` | `invalid_request` | `<ProviderName> userInfo sub does not match the id_token` |

An unknown, expired or reused `state` gets a 400 page, since there is no request to redirect to. A
real sign-in only accepts a provider's code: the mock IdP page and its form are refused for it.

## Triggers

| Sign-in | Triggers |
| --- | --- |
| First (user created) | `PreSignUp_ExternalProvider`, `PostConfirmation_ConfirmSignUp`, `TokenGeneration_HostedAuth` |
| Later, or a linked user | `PostAuthentication_Authentication`, `TokenGeneration_HostedAuth` |

`autoVerifyEmail` / `autoVerifyPhone` from PreSignUp set `email_verified` / `phone_number_verified`.
If PreSignUp links the identity to an existing user (`AdminLinkProviderForUser`), that user is
signed in instead of creating a new one.

## Tokens

The ID token carries `cognito:username` (`Google_1234`, or the linked user's name) and the
`identities` claim as an array where every field is a string: `"primary": "true"`,
`"dateCreated": "1642699117273"`, `"issuer": null` for social providers.

## Errors

All are redirects to `redirect_uri` with `error`, `error_description` and the app's `state`:

| Case | `error` | `error_description` |
| --- | --- | --- |
| IdP unknown in the pool | `invalid_request` | `Identity provider X is not configured in this user pool` |
| IdP not enabled on the client | `invalid_request` | `Identity provider X is not enabled for this app client` |
| IdP returned an error | as returned (`access_denied`) | as returned |
| Trigger failure | `invalid_request` | `PreSignUp failed with error <message>.` |
| Disabled user | `invalid_request` | `User is disabled.` |

## Limits

- SAML has no real mode: no SAML request, assertion parsing or signature checks.
- Real mode accepts `http://` endpoints and any port, so a local provider works; Cognito requires
  HTTPS on ports 80 and 443.
- Real mode sends a `nonce` to OIDC providers, and PKCE when the provider advertises `S256`; it
  caches JWKS for 10 minutes, where Cognito reads them for every `id_token`.
- For Google, real mode reads the OIDC userinfo endpoint from Google's discovery document, not the
  People API that Cognito uses as `attributes_url`; set `attributes_url` to change it.
- `AcrMapping`, `acr_values` and the `acr` / `amr` claims of a federated sign-in are not emulated.
- The PreAuthentication trigger does not run for a federated sign-in.
- AWS may show the provider prefix in lower case (`google_1234`) in some places, for example the
  PreSignUp event of case-insensitive pools. The emulator always uses the configured provider name.
- `AttributeMapping` is used as given; Cognito's automatic `username` mapping
  (`sub`, `id`, `user_id`) is applied only as a fallback.
