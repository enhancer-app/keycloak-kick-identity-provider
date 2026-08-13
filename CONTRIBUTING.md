# Contributing

## Prerequisites

- JDK 17
- Docker, only for `-PwithSmoke`

The Gradle wrapper downloads the required Gradle release; do not install Gradle globally.

## Validate a change

```bash
./gradlew build
./gradlew test -PwithSmoke
docker build -t keycloak-kick:local .
```

Keep the provider a thin Keycloak extension: do not add bundled Keycloak/Jackson/HTTP/logging
libraries, databases, deployment-specific configuration, client credentials, real tokens, or
realm imports. New handling for upstream data must fail closed and must not log raw payloads.

## Compatibility changes

Changes to Keycloak dependencies or SPI usage require an update to
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md), including the tested version and rationale.
