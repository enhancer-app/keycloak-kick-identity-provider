# Compatibility

## Supported Keycloak versions

| Provider release line | Compile target | Supported Keycloak versions | Tested container image |
| --- | --- | --- | --- |
| `1.x` | `26.5.2` | 26.5.x and later 26.x patch releases | `quay.io/keycloak/keycloak:26.5.2` |

This provider is built with Java 17. It uses public Keycloak provider SPIs where available and
the Keycloak-provided `org.keycloak.http.simple` HTTP API for profile retrieval.

## Why 26.5.x is the minimum

Keycloak moved `SimpleHttp`, `SimpleHttpRequest`, and `SimpleHttpResponse` to
`org.keycloak.http.simple` during the 26.x series. A JAR compiled for 26.5.2 cannot link against
the earlier package used by Keycloak 26.0–26.4. Supporting both would require reflective shims or
separate artifacts; this project intentionally does neither because that would make a security
critical OAuth provider harder to verify and maintain.

Keycloak versions before 26.5 are therefore unsupported by the `1.x` release line.

## Support policy

- Every release is compiled against one explicit Keycloak version and tested with that exact
  `quay.io/keycloak/keycloak` image.
- Patch releases within the same Keycloak 26.x minor line are expected to work, but only versions
  verified by CI are claimed as tested.
- A Keycloak major or minor release that changes a public SPI, dependency version, theme contract,
  or build augmentation behavior gets a compatibility investigation before being listed as
  supported.
- Do not deploy an untested provider JAR across a Keycloak major/minor upgrade. Upgrade Keycloak
  in staging, run `./gradlew test -PwithSmoke`, and complete the manual login check in
  [MANUAL_E2E.md](MANUAL_E2E.md) first.
- If a future Keycloak release requires source incompatibilities, it receives a new provider
  release line rather than runtime reflection or hidden compatibility behavior.

## Theme compatibility

The optional `kick` login theme extends `keycloak.v2` and explicitly includes
`css/styles.css css/kick-idp.css`. If the parent theme changes the name or location of its
stylesheet in a future Keycloak version, update `src/main/resources/theme/kick/login/theme.properties`
and verify the icon manually. The provider itself does not depend on the theme.
