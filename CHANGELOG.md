# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Added

- Initial Keycloak Kick social identity provider.
- OAuth 2.1 authorization-code flow with mandatory PKCE `S256`.
- Fixed Kick endpoints, validated profile parsing, safe token/profile error handling and bounded
  profile HTTP timeouts.
- Configurable email import, avatar attribute storage and username strategy.
- Unit tests and opt-in Keycloak 26.5.2 container discovery smoke test.
