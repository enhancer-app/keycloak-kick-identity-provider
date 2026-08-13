/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import io.github.enhancerapp.keycloak.kick.support.KeycloakStubs;
import io.github.enhancerapp.keycloak.kick.support.StubHttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.IdentityProviderModel;

/**
 * Security regression tests for the provider's deliberately small logging surface.
 *
 * <p>These don't merely assert that exceptions have a generic message. They capture emitted
 * records from the provider logger, concatenate messages and any attached throwable text, then
 * assert that high-value values supplied by the test cannot escape. A future "helpful" debug log
 * that includes a response body or bearer token fails these tests.
 */
class KickLogRedactionTest {

    private static final String ACCESS_TOKEN = "access-token-DO-NOT-LOG-47af";
    private static final String CLIENT_SECRET = "client-secret-DO-NOT-LOG-b816";
    private static final String AUTHORIZATION_CODE = "authorization-code-DO-NOT-LOG-8e11";
    private static final String PROFILE_PAYLOAD_SECRET = "profile-payload-DO-NOT-LOG-052a";

    private StubHttpServer server;
    private CapturingHandler handler;
    private java.util.logging.Logger logger;

    @BeforeEach
    void setUp() {
        server = new StubHttpServer();
        handler = new CapturingHandler();
        logger = java.util.logging.Logger.getLogger(KickIdentityProvider.class.getName());
        logger.setLevel(Level.ALL);
        logger.addHandler(handler);
    }

    @AfterEach
    void tearDown() {
        logger.removeHandler(handler);
        server.close();
    }

    @Test
    void non2xxResponseNeverLogsBearerTokenOrRemoteBody() {
        server.respondWith(401, "{\"detail\":\"" + PROFILE_PAYLOAD_SECRET + "\"}");

        assertThatThrownBy(() -> provider().doGetFederatedIdentity(ACCESS_TOKEN))
                .isInstanceOf(IdentityBrokerException.class);

        assertLogsAreFreeOfSecrets();
    }

    @Test
    void malformedProfileNeverLogsTheRemotePayload() {
        server.respondWith(200, "{\"data\":[{\"user_id\":{\"leak\":\""
                + PROFILE_PAYLOAD_SECRET + "\"}}]}");

        assertThatThrownBy(() -> provider().doGetFederatedIdentity(ACCESS_TOKEN))
                .isInstanceOf(IdentityBrokerException.class);

        assertLogsAreFreeOfSecrets();
    }

    @Test
    void malformedJsonNeverLogsTheRemotePayload() {
        server.respondWith(200, "{\"data\":[ " + PROFILE_PAYLOAD_SECRET);

        assertThatThrownBy(() -> provider().doGetFederatedIdentity(ACCESS_TOKEN))
                .isInstanceOf(IdentityBrokerException.class);

        assertLogsAreFreeOfSecrets();
    }

    @Test
    void missingTokenDoesNotLogAStringThatCouldContainOne() {
        assertThatThrownBy(() -> provider().doGetFederatedIdentity("  "))
                .isInstanceOf(IdentityBrokerException.class);

        assertLogsAreFreeOfSecrets();
    }

    @Test
    void tokenResponseMissingAccessTokenNeverEchoesItsPayload() {
        String response = "{\"refresh_token\":\"" + ACCESS_TOKEN + "\",\"detail\":\""
                + PROFILE_PAYLOAD_SECRET + "\"}";

        assertThatThrownBy(() -> provider().getFederatedIdentity(response))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessage(KickIdentityProvider.PROFILE_FAILURE_MESSAGE);

        assertLogsAreFreeOfSecrets();
    }

    @Test
    void malformedTokenResponseNeverEchoesItsPayload() {
        String response = "{\"access_token\": " + ACCESS_TOKEN;

        assertThatThrownBy(() -> provider().getFederatedIdentity(response))
                .isInstanceOf(IdentityBrokerException.class)
                .hasMessage(KickIdentityProvider.PROFILE_FAILURE_MESSAGE);

        assertLogsAreFreeOfSecrets();
    }

    @Test
    void configuredClientSecretAndAuthorizationCodeCannotReachProfileLogs() {
        // The profile code must never log these values even when the upstream fails. Keeping them
        // in this regression test matters: secrets often get added to an exception message while
        // diagnosing an unrelated failure path.
        server.respondWith(500, "{\"code\":\"" + AUTHORIZATION_CODE + "\",\"secret\":\""
                + CLIENT_SECRET + "\"}");

        assertThatThrownBy(() -> provider().doGetFederatedIdentity(ACCESS_TOKEN))
                .isInstanceOf(IdentityBrokerException.class);

        assertLogsAreFreeOfSecrets();
    }

    private KickIdentityProvider provider() {
        IdentityProviderModel model = new IdentityProviderModel();
        model.setAlias("kick");
        model.setConfig(new HashMap<>());
        model.getConfig().put("clientSecret", CLIENT_SECRET);

        return new KickIdentityProvider(
                KeycloakStubs.session(URI.create("https://sso.example.test/")).session(),
                new KickIdentityProviderConfig(model)) {
            @Override
            protected String getProfileUrl() {
                return server.url("/public/v1/users");
            }
        };
    }

    private void assertLogsAreFreeOfSecrets() {
        String records = handler.records().stream()
                .map(record -> record.getMessage() + " "
                        + (record.getThrown() == null ? "" : record.getThrown().toString()))
                .reduce("", (left, right) -> left + "\n" + right);

        org.assertj.core.api.Assertions.assertThat(records)
                .doesNotContain(ACCESS_TOKEN)
                .doesNotContain(CLIENT_SECRET)
                .doesNotContain(AUTHORIZATION_CODE)
                .doesNotContain(PROFILE_PAYLOAD_SECRET);
    }

    private static final class CapturingHandler extends Handler {
        private final List<LogRecord> records = new ArrayList<>();

        @Override
        public void publish(LogRecord record) {
            records.add(record);
        }

        @Override
        public void flush() {
            // In-memory only.
        }

        @Override
        public void close() {
            records.clear();
        }

        List<LogRecord> records() {
            return List.copyOf(records);
        }
    }
}
