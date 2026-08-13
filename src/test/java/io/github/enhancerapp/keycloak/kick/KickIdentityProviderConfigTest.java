/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import org.keycloak.OAuth2Constants;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;

class KickIdentityProviderConfigTest {

    private static KickIdentityProviderConfig configWith(Map<String, String> raw) {
        IdentityProviderModel model = new IdentityProviderModel();
        model.setProviderId(KickIdentityProviderFactory.PROVIDER_ID);
        model.setAlias(KickIdentityProviderFactory.PROVIDER_ID);
        model.setConfig(new HashMap<>(raw));
        KickIdentityProviderConfig config = new KickIdentityProviderConfig(model);
        config.applyFixedSettings();
        return config;
    }

    private static KickIdentityProviderConfig defaultConfig() {
        return configWith(Map.of());
    }

    @Nested
    @DisplayName("pinned endpoints")
    class PinnedEndpoints {

        @Test
        void areAppliedWhenNothingIsConfigured() {
            KickIdentityProviderConfig config = defaultConfig();

            assertThat(config.getAuthorizationUrl()).isEqualTo("https://id.kick.com/oauth/authorize");
            assertThat(config.getTokenUrl()).isEqualTo("https://id.kick.com/oauth/token");
            assertThat(config.getUserInfoUrl()).isEqualTo("https://api.kick.com/public/v1/users");
        }

        @Test
        @DisplayName("overwrite hostile values injected through the admin REST API or a realm import")
        void overwriteInjectedValues() {
            // The Admin Console does not render these fields for a social provider, but the admin
            // REST API and partial realm import accept an arbitrary config map. If those values
            // survived, an operator (or anyone who compromised an account with realm-manage
            // rights) could redirect the authorization code and the client secret to a host they
            // control, and make the Keycloak server itself issue requests to arbitrary URLs.
            KickIdentityProviderConfig config = configWith(Map.of(
                    "authorizationUrl", "https://attacker.example/authorize",
                    "tokenUrl", "http://169.254.169.254/latest/meta-data/",
                    "userInfoUrl", "http://localhost:8080/internal"));

            assertThat(config.getAuthorizationUrl()).isEqualTo(KickEndpoints.AUTHORIZATION_URL);
            assertThat(config.getTokenUrl()).isEqualTo(KickEndpoints.TOKEN_URL);
            assertThat(config.getUserInfoUrl()).isEqualTo(KickEndpoints.PROFILE_URL);
        }

        @Test
        void areAllHttpsUrlsOnTheKickDomain() {
            assertThat(KickEndpoints.AUTHORIZATION_URL).startsWith("https://id.kick.com/");
            assertThat(KickEndpoints.TOKEN_URL).startsWith("https://id.kick.com/");
            assertThat(KickEndpoints.PROFILE_URL).startsWith("https://api.kick.com/");
        }
    }

    @Nested
    @DisplayName("PKCE")
    class Pkce {

        @Test
        void isForcedOnWithS256() {
            KickIdentityProviderConfig config = defaultConfig();

            assertThat(config.isPkceEnabled()).isTrue();
            assertThat(config.getPkceMethod()).isEqualTo(OAuth2Constants.PKCE_METHOD_S256);
        }

        @Test
        @DisplayName("cannot be disabled or downgraded to 'plain' through configuration")
        void cannotBeWeakened() {
            KickIdentityProviderConfig config = configWith(Map.of(
                    "pkceEnabled", "false",
                    "pkceMethod", OAuth2Constants.PKCE_METHOD_PLAIN));

            assertThat(config.isPkceEnabled()).isTrue();
            assertThat(config.getPkceMethod()).isEqualTo(OAuth2Constants.PKCE_METHOD_S256);
        }
    }

    @Nested
    @DisplayName("scopes")
    class Scopes {

        @Test
        void defaultToUserRead() {
            assertThat(defaultConfig().getDefaultScope()).isEqualTo("user:read");
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "   "})
        void defaultAppliesWhenTheAdministratorClearsTheField(String configured) {
            assertThat(configWith(Map.of("defaultScope", configured)).getDefaultScope()).isEqualTo("user:read");
        }

        @Test
        void anExplicitScopeIsRespected() {
            // Unlike the endpoints, the scope is a legitimate administrator choice.
            assertThat(configWith(Map.of("defaultScope", "user:read channel:read")).getDefaultScope())
                    .isEqualTo("user:read channel:read");
        }
    }

    @Nested
    @DisplayName("client authentication")
    class ClientAuthentication {

        @Test
        void defaultsToClientSecretPostAsRequiredByKick() {
            assertThat(defaultConfig().getClientAuthMethod()).isEqualTo(OIDCLoginProtocol.CLIENT_SECRET_POST);
            assertThat(defaultConfig().isBasicAuthentication()).isFalse();
            assertThat(defaultConfig().isJWTAuthentication()).isFalse();
        }
    }

    @Nested
    @DisplayName("Kick specific options")
    class KickOptions {

        @Test
        void emailImportIsDisabledByDefault() {
            assertThat(defaultConfig().isImportEmail()).isFalse();
        }

        @Test
        void avatarStorageIsEnabledByDefault() {
            // Guards against the Boolean.parseBoolean trap: an absent value must mean the
            // documented default (on), not false.
            assertThat(defaultConfig().isStoreAvatar()).isTrue();
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "   "})
        void aBlankFlagMeansUnsetNotFalse(String blank) {
            assertThat(configWith(Map.of(KickIdentityProviderConfig.STORE_AVATAR, blank)).isStoreAvatar()).isTrue();
            assertThat(configWith(Map.of(KickIdentityProviderConfig.IMPORT_EMAIL, blank)).isImportEmail()).isFalse();
        }

        @Test
        void explicitFlagsAreHonoured() {
            assertThat(configWith(Map.of(KickIdentityProviderConfig.STORE_AVATAR, "false")).isStoreAvatar()).isFalse();
            assertThat(configWith(Map.of(KickIdentityProviderConfig.IMPORT_EMAIL, "true")).isImportEmail()).isTrue();
        }

        @Test
        void avatarAttributeDefaultsAndTrims() {
            assertThat(defaultConfig().getAvatarAttribute()).isEqualTo("kick_profile_picture");
            assertThat(configWith(Map.of(KickIdentityProviderConfig.AVATAR_ATTRIBUTE, "  picture  "))
                    .getAvatarAttribute()).isEqualTo("picture");
            assertThat(configWith(Map.of(KickIdentityProviderConfig.AVATAR_ATTRIBUTE, "   "))
                    .getAvatarAttribute()).isEqualTo("kick_profile_picture");
        }

        @Test
        void usernameStrategyDefaultsToTheStableId() {
            assertThat(defaultConfig().getUsernameStrategy()).isEqualTo(KickUsernameStrategy.STABLE_ID_PREFIX);
            assertThat(defaultConfig().getUsernamePrefix()).isEqualTo("kick-");
        }

        @Test
        void usernameStrategyIsReadFromConfiguration() {
            assertThat(configWith(Map.of(KickIdentityProviderConfig.USERNAME_STRATEGY, "provider-username"))
                    .getUsernameStrategy()).isEqualTo(KickUsernameStrategy.PROVIDER_USERNAME);
        }

        @Test
        void settersRoundTripThroughTheConfigMap() {
            KickIdentityProviderConfig config = defaultConfig();
            config.setImportEmail(true);
            config.setStoreAvatar(false);
            config.setAvatarAttribute("avatar");
            config.setUsernameStrategy(KickUsernameStrategy.PROVIDER_USERNAME);
            config.setUsernamePrefix("k_");

            assertThat(config.isImportEmail()).isTrue();
            assertThat(config.isStoreAvatar()).isFalse();
            assertThat(config.getAvatarAttribute()).isEqualTo("avatar");
            assertThat(config.getUsernameStrategy()).isEqualTo(KickUsernameStrategy.PROVIDER_USERNAME);
            assertThat(config.getUsernamePrefix()).isEqualTo("k_");
        }
    }

    @Nested
    @DisplayName("Keycloak validation")
    class KeycloakValidation {

        @Test
        void theFixedConfigurationPassesKeycloaksOwnValidation() {
            // OAuth2IdentityProviderConfig#validate rejects an unsupported PKCE method and any
            // endpoint that violates the realm's SSL policy. Running it proves the pinned values
            // are a combination Keycloak itself accepts, including under the strictest policy.
            RealmModel realm = Mockito.mock(RealmModel.class);
            Mockito.when(realm.getSslRequired()).thenReturn(SslRequired.ALL);

            defaultConfig().validate(realm);
        }
    }
}
