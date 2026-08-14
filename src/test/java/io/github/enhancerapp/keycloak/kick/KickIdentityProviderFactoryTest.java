/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.keycloak.provider.ProviderConfigProperty;

class KickIdentityProviderFactoryTest {

    private final KickIdentityProviderFactory factory = new KickIdentityProviderFactory();

    @Test
    void registersAsKick() {
        assertThat(factory.getId()).isEqualTo("kick");
        assertThat(factory.getName()).isEqualTo("Kick");
    }

    @Test
    void newConfigurationIsSafeByDefault() {
        KickIdentityProviderConfig config = factory.createConfig();

        assertThat(config.getAuthorizationUrl()).isEqualTo(KickEndpoints.AUTHORIZATION_URL);
        assertThat(config.getTokenUrl()).isEqualTo(KickEndpoints.TOKEN_URL);
        assertThat(config.getUserInfoUrl()).isEqualTo(KickEndpoints.PROFILE_URL);
        assertThat(config.isPkceEnabled()).isTrue();
        assertThat(config.getPkceMethod()).isEqualTo("S256");
        assertThat(config.getDefaultScope()).isEqualTo("user:read");
    }

    @Test
    void exposesOnlyKickSpecificOptionsAndNeverEndpointOverrides() {
        Map<String, ProviderConfigProperty> properties = factory.getConfigProperties().stream()
                .collect(Collectors.toMap(ProviderConfigProperty::getName, property -> property));

        assertThat(properties).containsOnlyKeys(
                "authorizationUrl",
                "tokenUrl",
                "userInfoUrl",
                KickIdentityProviderConfig.USERNAME_STRATEGY,
                KickIdentityProviderConfig.USERNAME_PREFIX);
    }

    @Test
    void exposesDocumentedDefaults() {
        Map<String, ProviderConfigProperty> properties = factory.getConfigProperties().stream()
                .collect(Collectors.toMap(ProviderConfigProperty::getName, property -> property));

        assertThat(properties.get("authorizationUrl").getDefaultValue()).isEqualTo(KickEndpoints.AUTHORIZATION_URL);
        assertThat(properties.get(KickIdentityProviderConfig.USERNAME_STRATEGY).getDefaultValue())
                .isEqualTo("stable-id-prefix");
        assertThat(properties.get(KickIdentityProviderConfig.USERNAME_PREFIX).getDefaultValue()).isEqualTo("kick-");
    }
}
