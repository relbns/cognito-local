# Federated identity providers (mock IdP)

cognito-local emulates sign-in through a third-party identity provider (Google, Facebook,
LoginWithAmazon, SignInWithApple, OIDC, SAML) without any network call. A built-in mock IdP page
stands in for the provider, and everything after it follows the Cognito contract.

## Setup

1. Create the IdP on the pool with `CreateIdentityProvider` (name, type, `ProviderDetails`,
   `AttributeMapping`, optional `IdpIdentifiers`).
2. Enable it on the app client: `SupportedIdentityProviders: ["COGNITO", "Google", ...]`, with
   `AllowedOAuthFlows`, `AllowedOAuthScopes` and `CallbackURLs` as usual.

## Flow

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

- No real IdP protocol: no OIDC token exchange, no SAML assertion parsing or signature checks.
- The PreAuthentication trigger does not run for a federated sign-in.
- AWS may show the provider prefix in lower case (`google_1234`) in some places, for example the
  PreSignUp event of case-insensitive pools. The emulator always uses the configured provider name.
- `AttributeMapping` is used as given; Cognito's automatic `username` mapping
  (`sub`, `id`, `user_id`) is applied only as a fallback.
