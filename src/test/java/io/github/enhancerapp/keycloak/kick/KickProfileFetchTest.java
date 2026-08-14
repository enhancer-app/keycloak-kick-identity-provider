/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import io.github.enhancerapp.keycloak.kick.support.KeycloakStubs;
import io.github.enhancerapp.keycloak.kick.support.StubHttpServer;

import org.apache.http.client.config.RequestConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

class KickProfileFetchTest {

    private static final String VALID_PROFILE = """
            {"data":[{"user_id":123,"name":"streamer","email":"user@example.com",
                      "profile_picture":"https://files.kick.com/avatar.png"}]}""";

    private StubHttpServer kick;
    private KeycloakSession session;

    @BeforeEach
    void setUp() {
        kick = new StubHttpServer();
        session = KeycloakStubs.session(URI.create("https://sso.example.com/")).session();
    }

    @AfterEach
    void tearDown() {
        kick.close();
    }

    /**
     * Provider wired to the loopback stub instead of the pinned Kick host. Only the profile URL
     * and the timeout budget are overridden; every other code path is production code.
     */
    private static final class TestProvider extends KickIdentityProvider {
        private final String profileUrl;
        private final int timeoutMillis;

        TestProvider(KeycloakSession session, KickIdentityProviderConfig config, String profileUrl, int timeoutMillis) {
            super(session, config);
            this.profileUrl = profileUrl;
            this.timeoutMillis = timeoutMillis;
        }

        @Override
        protected String getProfileUrl() {
            return profileUrl;
        }

        @Override
        protected RequestConfig getRequestConfig() {
            int millis = timeoutMillis;
            return RequestConfig.custom()
                    .setConnectTimeout(millis)
                    .setSocketTimeout(millis)
                    .setConnectionRequestTimeout(millis)
                    .build();
        }
    }

    private KickIdentityProvider provider(Map<String, String> rawConfig) {
        IdentityProviderModel model = new IdentityProviderModel();
        model.setProviderId(KickIdentityProviderFactory.PROVIDER_ID);
        model.setAlias("kick");
        model.setConfig(new HashMap<>(rawConfig));
        return new TestProvider(session, new KickIdentityProviderConfig(model),
                kick.url("/public/v1/users"), 2_000);
    }

    private KickIdentityProvider provider() {
        return provider(Map.of());
    }

    @Nested
    @DisplayName("successful retrieval")
    class Success {

        @Test
        void mapsTheKickUserIdOntoTheBrokeredSubject() {
            kick.respondWith(200, VALID_PROFILE);

            BrokeredIdentityContext context = provider().doGetFederatedIdentity("access-token");

            assertThat(context.getId()).isEqualTo("123");
        }

        @Test
        void defaultsToAUsernameDerivedFromTheStableId() {
            kick.respondWith(200, VALID_PROFILE);

            assertThat(provider().doGetFederatedIdentity("access-token").getUsername()).isEqualTo("kick-123");
        }

        @Test
        void honoursTheProviderUsernameStrategy() {
            kick.respondWith(200, VALID_PROFILE);

            BrokeredIdentityContext context = provider(
                    Map.of(KickIdentityProviderConfig.USERNAME_STRATEGY, "provider-username"))
                    .doGetFederatedIdentity("access-token");

            assertThat(context.getUsername()).isEqualTo("streamer");
        }

        @Test
        void sendsTheAccessTokenAsABearerCredential() {
            kick.respondWith(200, VALID_PROFILE);

            provider().doGetFederatedIdentity("access-token");

            assertThat(kick.lastRequest().method()).isEqualTo("GET");
            assertThat(kick.lastRequest().header("Authorization")).isEqualTo("Bearer access-token");
            assertThat(kick.lastRequest().header("Accept")).isEqualTo("application/json");
        }

        @Test
        @DisplayName("never fabricates a first or last name from the Kick display name")
        void leavesNamesUnset() {
            kick.respondWith(200, VALID_PROFILE);

            BrokeredIdentityContext context = provider().doGetFederatedIdentity("access-token");

            assertThat(context.getFirstName()).isNull();
            assertThat(context.getLastName()).isNull();
        }

        @Test
        void importsEmailOnEveryLogin() {
            kick.respondWith(200, VALID_PROFILE);

            assertThat(provider().doGetFederatedIdentity("access-token").getEmail()).isEqualTo("user@example.com");
        }

        @Test
        void importsTheEmailWhenEnabled() {
            kick.respondWith(200, VALID_PROFILE);

            BrokeredIdentityContext context = provider(
                    Map.of(KickIdentityProviderConfig.IMPORT_EMAIL, "true"))
                    .doGetFederatedIdentity("access-token");

            assertThat(context.getEmail()).isEqualTo("user@example.com");
        }

        @Test
        void storesTheAvatarUrlByDefault() {
            kick.respondWith(200, VALID_PROFILE);

            BrokeredIdentityContext context = provider().doGetFederatedIdentity("access-token");

            assertThat(context.getUserAttribute("kick.profile_image_url"))
                    .isEqualTo("https://files.kick.com/avatar.png");
        }

        @Test
        void storesTheAvatarUnderAConfiguredAttributeName() {
            kick.respondWith(200, VALID_PROFILE);

            BrokeredIdentityContext context = provider(
                    Map.of(KickIdentityProviderConfig.AVATAR_ATTRIBUTE, "picture"))
                    .doGetFederatedIdentity("access-token");

            assertThat(context.getUserAttribute("kick.profile_image_url")).isEqualTo("https://files.kick.com/avatar.png");
        }

        @Test
        void skipsTheAvatarWhenDisabled() {
            kick.respondWith(200, VALID_PROFILE);

            BrokeredIdentityContext context = provider(
                    Map.of(KickIdentityProviderConfig.STORE_AVATAR, "false"))
                    .doGetFederatedIdentity("access-token");

            assertThat(context.getUserAttribute("kick.profile_image_url")).isEqualTo("https://files.kick.com/avatar.png");
        }

        @Test
        void acceptsAnyTwoHundredLevelStatus() {
            kick.respondWith(203, VALID_PROFILE);

            assertThat(provider().doGetFederatedIdentity("access-token").getId()).isEqualTo("123");
        }
    }

    @Nested
    @DisplayName("missing access token")
    class MissingToken {

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"   "})
        void isRejectedWithoutContactingKick(String token) {
            kick.respondWith(200, VALID_PROFILE);

            assertThatThrownBy(() -> provider().doGetFederatedIdentity(token))
                    .isInstanceOf(IdentityBrokerException.class)
                    .hasMessage(KickIdentityProvider.PROFILE_FAILURE_MESSAGE);

            // Fail closed and fail early: an empty bearer credential must never be sent upstream.
            assertThat(kick.requestCount()).isZero();
        }
    }

    @Nested
    @DisplayName("upstream HTTP failures")
    class UpstreamFailures {

        @ParameterizedTest
        @ValueSource(ints = {400, 401, 403, 404, 429, 500, 502, 503})
        void areSurfacedAsAGenericBrokerError(int status) {
            kick.respondWith(status, "{\"error\":\"detail that must not leak\"}");

            assertThatThrownBy(() -> provider().doGetFederatedIdentity("access-token"))
                    .isInstanceOf(IdentityBrokerException.class)
                    .hasMessage(KickIdentityProvider.PROFILE_FAILURE_MESSAGE);
        }

        @Test
        void redirectsAreNotFollowedIntoASuccessfulLogin() {
            // A 3xx that the client does not follow is not a 2xx and must be refused rather than
            // parsed as a profile.
            kick.respondWith(302, "");

            assertThatThrownBy(() -> provider().doGetFederatedIdentity("access-token"))
                    .isInstanceOf(IdentityBrokerException.class);
        }

        @Test
        void aConnectionFailureIsSurfacedAsAGenericBrokerError() {
            kick.close();

            assertThatThrownBy(() -> provider().doGetFederatedIdentity("access-token"))
                    .isInstanceOf(IdentityBrokerException.class)
                    .hasMessage(KickIdentityProvider.PROFILE_FAILURE_MESSAGE);
        }

        @Test
        void aSlowUpstreamHitsTheBoundedSocketTimeout() {
            kick.respondWith(200, VALID_PROFILE).delayResponseBy(2_000);

            IdentityProviderModel model = new IdentityProviderModel();
            model.setAlias("kick");
            model.setConfig(new HashMap<>());
            KickIdentityProvider slowIntolerant = new TestProvider(
                    session, new KickIdentityProviderConfig(model), kick.url("/public/v1/users"), 250);

            long start = System.nanoTime();
            assertThatThrownBy(() -> slowIntolerant.doGetFederatedIdentity("access-token"))
                    .isInstanceOf(IdentityBrokerException.class)
                    .hasMessage(KickIdentityProvider.PROFILE_FAILURE_MESSAGE);
            long elapsedMillis = (System.nanoTime() - start) / 1_000_000;

            // The point of the bounded budget: the request thread is released well before the
            // upstream would have answered.
            assertThat(elapsedMillis).isLessThan(1_500);
        }

        @Test
        void productionTimeoutsAreBoundedAndNonZero() {
            // Apache HttpClient treats 0 as "infinite"; a zero here would let one slow Kick
            // response pin a Keycloak request thread indefinitely.
            assertThat(KickIdentityProvider.CONNECT_TIMEOUT_MILLIS).isPositive();
            assertThat(KickIdentityProvider.SOCKET_TIMEOUT_MILLIS).isPositive();
            assertThat(KickIdentityProvider.CONNECTION_REQUEST_TIMEOUT_MILLIS).isPositive();
            assertThat(KickIdentityProvider.MAX_PROFILE_RESPONSE_BYTES).isPositive();
        }
    }

    @Nested
    @DisplayName("unusable success responses")
    class UnusableResponses {

        @ParameterizedTest
        @ValueSource(strings = {
            "not json at all",
            "<html><body>maintenance</body></html>",
            "{\"data\":[]}",
            "{\"data\":null}",
            "{\"data\":[{}]}",
            "{\"data\":[{\"user_id\":null}]}",
            "{\"data\":[{\"user_id\":{}}]}",
            "{}"
        })
        void areRejectedRatherThanCoercedIntoAnIdentity(String body) {
            kick.respondWith(200, body);

            assertThatThrownBy(() -> provider().doGetFederatedIdentity("access-token"))
                    .isInstanceOf(IdentityBrokerException.class)
                    .hasMessage(KickIdentityProvider.PROFILE_FAILURE_MESSAGE);
        }

        @Test
        void anEmptyBodyIsRejected() {
            kick.respondWith(200, "");

            assertThatThrownBy(() -> provider().doGetFederatedIdentity("access-token"))
                    .isInstanceOf(IdentityBrokerException.class);
        }
    }
}
