# syntax=docker/dockerfile:1
#
# Build a Keycloak image with the Kick social identity provider installed.
#
# Build context must contain the provider JAR. The default command below builds it first:
#   docker build -t keycloak-kick:local .
#
# No Keycloak realm, administrator account, client credentials, OAuth secrets or deployment
# endpoint is baked into this image. Configure those at deployment time using normal Keycloak
# mechanisms.

FROM quay.io/keycloak/keycloak:26.5.2 AS builder

COPY build/libs/keycloak-kick-identity-provider-*.jar /opt/keycloak/providers/

# Provider discovery is a build-time augmentation step in Keycloak's Quarkus distribution.
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.5.2

COPY --from=builder /opt/keycloak/ /opt/keycloak/

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start"]
