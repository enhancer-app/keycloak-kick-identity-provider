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
        assertThat(config.isImportEmail()).isFalse();
        assertThat(config.isStoreAvatar()).isTrue();
    }

    @Test
    void exposesOnlyKickSpecificOptionsAndNeverEndpointOverrides() {
        Map<String, ProviderConfigProperty> properties = factory.getConfigProperties().stream()
                .collect(Collectors.toMap(ProviderConfigProperty::getName, property -> property));

        assertThat(properties).containsOnlyKeys(
                KickIdentityProviderConfig.IMPORT_EMAIL,
                KickIdentityProviderConfig.STORE_AVATAR,
                KickIdentityProviderConfig.AVATAR_ATTRIBUTE,
                KickIdentityProviderConfig.USERNAME_STRATEGY,
                KickIdentityProviderConfig.USERNAME_PREFIX);
        assertThat(properties).doesNotContainKeys("authorizationUrl", "tokenUrl", "userInfoUrl");
    }

    @Test
    void exposesDocumentedDefaults() {
        Map<String, ProviderConfigProperty> properties = factory.getConfigProperties().stream()
                .collect(Collectors.toMap(ProviderConfigProperty::getName, property -> property));

        assertThat(properties.get(KickIdentityProviderConfig.IMPORT_EMAIL).getDefaultValue()).isEqualTo(false);
        assertThat(properties.get(KickIdentityProviderConfig.STORE_AVATAR).getDefaultValue()).isEqualTo(true);
        assertThat(properties.get(KickIdentityProviderConfig.AVATAR_ATTRIBUTE).getDefaultValue())
                .isEqualTo("kick_profile_picture");
        assertThat(properties.get(KickIdentityProviderConfig.USERNAME_STRATEGY).getDefaultValue())
                .isEqualTo("stable-id-prefix");
        assertThat(properties.get(KickIdentityProviderConfig.USERNAME_PREFIX).getDefaultValue()).isEqualTo("kick-");
    }
}
