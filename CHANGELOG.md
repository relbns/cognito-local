# Changelog

Each release is also on [GitHub releases](https://github.com/relbns/cognito-local/releases), with
these notes.

## 1.0.1

- Installing the package no longer pulls in its development dependencies: the published
  `npm-shrinkwrap.json` now lists only the runtime tree, so an install is about 50 MB.
- The repository uses `package-lock.json` again; the shrinkwrap is generated from it when the
  package is packed. npm 12 ignores `npm-shrinkwrap.json`, so pinned installs need npm 10 or 11.

## 1.0.0

First release of `cognito-emulator`, a local emulator of the Amazon Cognito User Pools API for
development and tests.

- 122 API operations for the AWS SDK for JavaScript v2 and v3, boto3 and the AWS CLI v2, checked
  against the API model.
- Stateful CUSTOM_AUTH challenges with Define, Create and Verify triggers from local JavaScript files.
- Hosted login with sign-up, confirm, forgot-password and MFA setup pages, and the OAuth2 and OIDC
  endpoints with PKCE.
- Passkeys: WebAuthn registration and `WEB_AUTHN` sign-in in `USER_AUTH`.
- Federated sign-in through a mock identity provider, with attribute mapping and linked users.
- Access and refresh token checks, `SECRET_HASH`, password policy and sign-in lockout as Cognito
  applies them, each with a switch for lenient behaviour.
- Admin UI with a codes viewer and a token decoder.
- Seed files and export, the `start`, `status`, `seed`, `export` and `reset` commands, and a
  multi-arch Docker image on GitHub Container Registry.
