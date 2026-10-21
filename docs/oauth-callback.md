# OAuth callback page (dev tool)

`/_admin/callback` is a page of the admin UI that plays the part of your app's redirect URI. It is a
cognito-emulator development tool, not something Amazon Cognito has. Use it to try the hosted login
(`/oauth2/authorize`) and federated sign-in without writing a client.

## Setup

Add the page to the app client's `CallbackURLs`, with the port you run on:

```json
"CallbackURLs": ["http://localhost:9229/_admin/callback"]
```

The client also needs `AllowedOAuthFlowsUserPoolClient: true`, `AllowedOAuthFlows: ["code"]` and
`AllowedOAuthScopes`. To sign in through an identity provider, list it in
`SupportedIdentityProviders` (see [federation](federation.md)).

## Use

1. Open `http://localhost:9229/_admin/callback`, pick the app client, optionally an identity
   provider (`COGNITO` or a provider name of the pool) and scopes, and keep PKCE on or off.
2. **Build authorize URL** shows the `/oauth2/authorize` URL with this page as `redirect_uri`, and
   warns when the page is not in the client's `CallbackURLs` or the provider does not exist.
3. Follow the link and sign in on the built-in login page or the mock IdP. The login page also
   links the sign-up and forgot-password pages, which come back here after a confirmed sign-up.
4. The redirect lands back on `/_admin/callback` with `code` and `state` (or `error` and
   `error_description`). The client and the PKCE verifier of a login started here are filled in.
5. **Exchange code** posts to `/oauth2/token`, sending the client secret from the emulator's store
   with HTTP Basic auth when the client has one. The page shows the token response, whether a
   refresh token came back, and the decoded ID and access tokens checked against the pool's JWKS,
   issuer, expiry and client id.

A login started elsewhere works too: pick the client and paste the PKCE verifier if one was used.

## Notes

- The redirect URI is built from the host and port of the request, so open the page on the same
  host name you registered (`localhost`, not `127.0.0.1`, if that is what `CallbackURLs` has).
- Pending logins are kept in memory for ten minutes.
- After one sign-in the browser keeps a hosted login session for an hour, so the next authorize URL
  of the same pool returns a code without the form. Add `prompt=login` to the URL to sign in again,
  or open `/logout?client_id=<id>&logout_uri=<url>` with one of the client's `LogoutURLs`.
- Like the rest of the admin UI it is open unless an admin token is set (see the README's
  "Admin token"), and it is off with `--no-admin`.
