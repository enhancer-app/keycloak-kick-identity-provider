# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected security vulnerability. Report it privately through
the repository's GitHub Security Advisories reporting channel:

<https://github.com/enhancer-app/keycloak-kick-identity-provider/security/advisories/new>

Include the affected version, Keycloak version, deployment assumptions required to reproduce the
issue, and a minimal proof of concept. Do not include access tokens, refresh tokens, client
secrets, authorization codes, or real profile data.

## Supported versions

The current release line supports Keycloak 26.5.x and later 26.x patch releases, subject to the
compatibility policy in [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md). Security fixes are applied
to the latest release line first.

## Security design constraints

- OAuth endpoints are compiled in and cannot be changed by realm configuration.
- PKCE is always enabled with `S256`.
- Profile identity uses only Kick `data[0].user_id`.
- HTTP requests have bounded connection, socket and connection-pool timeouts.
- Profile and token-response failures use fixed error messages. Tokens, authorization codes,
  client secrets and remote response bodies are never written to provider logs.
- The provider is thin: it bundles no Keycloak, Jackson, HTTP client or logging dependency.
