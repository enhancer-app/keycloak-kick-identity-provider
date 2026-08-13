/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import io.github.enhancerapp.keycloak.kick.support.FormCodec;
import io.github.enhancerapp.keycloak.kick.support.KeycloakStubs;
import io.github.enhancerapp.keycloak.kick.support.StubHttpServer;

import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Verifies the two halves of the authorization code flow that carry the security guarantees:
 * the outbound authorization request (PKCE S256) and the code-for-token exchange.
 *
 * <p>Both are driven through Keycloak's own broker plumbing rather than reimplemented, so the
 * assertions describe what a Kick server would actually receive.
 */
class KickOAuthFlowTest {

    private static final String BASE_URI = "https://sso.example.com/";
    private static final String REALM = "demo";
    private static final String ALIAS = "kick";
    private static final String CLIENT_ID = "kick-client-id";
    private static final String CLIENT_SECRET = "kick-client-secret-2f9a";
    private static final String REDIRECT_URI =
            "https://sso.example.com/realms/demo/broker/kick/endpoint";

    private KeycloakStubs.Session stubs;
    private RealmModel realm;

    @BeforeEach
    void setUp() {
        realm = KeycloakStubs.realm(REALM);
        stubs = KeycloakStubs.session(URI.create(BASE_URI), realm);
    }

    private KickIdentityProvider provider(Map<String, String> extraConfig) {
        Map<String, String> raw = new HashMap<>(extraConfig);
        raw.put("clientId", CLIENT_ID);
        raw.put("clientSecret", CLIENT_SECRET);

        IdentityProviderModel model = new IdentityProviderModel();
        model.setProviderId(KickIdentityProviderFactory.PROVIDER_ID);
        model.setAlias(ALIAS);
        model.setConfig(raw);
        return new KickIdentityProvider(stubs.session(), new KickIdentityProviderConfig(model));
    }

    private static String s256(String codeVerifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Authorization request
    // ---------------------------------------------------------------------------------------

    @Nested
    @DisplayName("authorization request")
    class AuthorizationRequest {

        private AuthenticationSessionModel authSession;
        private Map<String, String> query;

        private Map<String, String> performLogin(KickIdentityProvider provider) {
            authSession = mock(AuthenticationSessionModel.class);
            IdentityBrokerState state =
                    IdentityBrokerState.decoded("state-value", null, "app-client", "tab-id", null);
            AuthenticationRequest request = new AuthenticationRequest(
                    stubs.session(), realm, authSession, stubs.context().getHttpRequest(),
                    stubs.uriInfo(), state, REDIRECT_URI);

            Response response = provider.performLogin(request);
            assertThat(response.getStatus()).isEqualTo(Response.Status.SEE_OTHER.getStatusCode());

            URI location = response.getLocation();
            assertThat(location.getScheme()).isEqualTo("https");
            assertThat(location.getHost()).isEqualTo("id.kick.com");
            assertThat(location.getPath()).isEqualTo("/oauth/authorize");

            query = FormCodec.parse(location.getRawQuery());
            return query;
        }

        private String capturedCodeVerifier() {
            ArgumentCaptor<String> value = ArgumentCaptor.forClass(String.class);
            Mockito.verify(authSession).setClientNote(eq("BROKER_CODE_CHALLENGE"), value.capture());
            return value.getValue();
        }

        @Test
        void targetsThePinnedKickAuthorizationEndpoint() {
            performLogin(provider(Map.of()));
        }

        @Test
        void isAnAuthorizationCodeRequestForTheConfiguredClient() {
            Map<String, String> q = performLogin(provider(Map.of()));

            assertThat(q).containsEntry("response_type", "code");
            assertThat(q).containsEntry("client_id", CLIENT_ID);
            assertThat(q).containsEntry("redirect_uri", REDIRECT_URI);
            assertThat(q).containsEntry("scope", "user:read");
            assertThat(q).containsEntry("state", "state-value.tab-id.YXBwLWNsaWVudA");
        }

        @Test
        void usesTheConfiguredScopeWhenTheAdministratorSetsOne() {
            Map<String, String> q = performLogin(provider(Map.of("defaultScope", "user:read channel:read")));

            assertThat(q).containsEntry("scope", "user:read channel:read");
        }

        @Test
        @DisplayName("advertises PKCE with the S256 challenge method")
        void announcesS256() {
            Map<String, String> q = performLogin(provider(Map.of()));

            assertThat(q).containsEntry("code_challenge_method", OAuth2Constants.PKCE_METHOD_S256);
            assertThat(q).containsKey("code_challenge");
        }

        @Test
        @DisplayName("the advertised challenge is the SHA-256 of the verifier kept in the auth session")
        void challengeIsTheS256OfTheStoredVerifier() {
            Map<String, String> q = performLogin(provider(Map.of()));

            String verifier = capturedCodeVerifier();
            assertThat(verifier).isNotBlank();
            // Proving the actual cryptographic relationship, not just the presence of a parameter:
            // a challenge unrelated to the stored verifier would make PKCE decorative.
            assertThat(q.get("code_challenge")).isEqualTo(s256(verifier));
        }

        @Test
        void theChallengeIsNotThePlainVerifier() {
            Map<String, String> q = performLogin(provider(Map.of()));

            assertThat(q.get("code_challenge")).isNotEqualTo(capturedCodeVerifier());
        }

        @Test
        void recordsS256AsTheChallengeMethodInTheAuthSession() {
            performLogin(provider(Map.of()));

            Mockito.verify(authSession)
                    .setClientNote("BROKER_CODE_CHALLENGE_METHOD", OAuth2Constants.PKCE_METHOD_S256);
        }

        @Test
        @DisplayName("PKCE stays on even when the stored configuration says otherwise")
        void pkceCannotBeTurnedOffByConfiguration() {
            Map<String, String> q = performLogin(provider(Map.of(
                    "pkceEnabled", "false",
                    "pkceMethod", OAuth2Constants.PKCE_METHOD_PLAIN)));

            assertThat(q).containsEntry("code_challenge_method", OAuth2Constants.PKCE_METHOD_S256);
            assertThat(q.get("code_challenge")).isEqualTo(s256(capturedCodeVerifier()));
        }

        @Test
        void aFreshVerifierIsGeneratedPerAuthorizationRequest() {
            performLogin(provider(Map.of()));
            String first = capturedCodeVerifier();

            performLogin(provider(Map.of()));
            String second = capturedCodeVerifier();

            assertThat(second).isNotEqualTo(first);
        }

        @Test
        void theClientSecretNeverAppearsInTheAuthorizationUrl() {
            Map<String, String> q = performLogin(provider(Map.of()));

            assertThat(q.values()).noneMatch(v -> v.contains(CLIENT_SECRET));
        }
    }

    // ---------------------------------------------------------------------------------------
    // Token exchange
    // ---------------------------------------------------------------------------------------

    @Nested
    @DisplayName("token exchange")
    class TokenExchange {

        private StubHttpServer kickToken;

        @BeforeEach
        void startStub() {
            kickToken = new StubHttpServer();
            kickToken.respondWith(200, "{\"access_token\":\"at\",\"token_type\":\"Bearer\"}");
        }

        @AfterEach
        void stopStub() {
            kickToken.close();
        }

        /**
         * Drives Keycloak's own {@code Endpoint#generateTokenRequest} and sends the result to the
         * stub server, returning the form parameters Kick would have received.
         *
         * <p>{@code Endpoint} is a protected nested class of {@code AbstractOAuth2IdentityProvider}
         * and therefore unreachable from this package; it is obtained through the public
         * {@code callback} factory and invoked reflectively. A rename in a future Keycloak release
         * fails this test loudly, which is the intended signal for a version-pinned provider.
         */
        private Map<String, String> exchange(String encodedState, AuthenticationSessionModel authSession) {
            KickIdentityProvider provider = provider(Map.of());
            // Redirect the exchange to the loopback stub. Production code cannot do this: the URL
            // is re-pinned by applyFixedSettings on every provider instantiation.
            provider.getConfig().setTokenUrl(kickToken.url("/oauth/token"));

            if (encodedState != null) {
                stubs.queryParameters().putSingle(OAuth2Constants.STATE, encodedState);
            }

            ClientModel client = mock(ClientModel.class);
            when(realm.getClientByClientId(anyString())).thenReturn(client);

            Object endpoint = provider.callback(realm, mock(UserAuthenticationIdentityProvider.AuthenticationCallback.class),
                    mock(EventBuilder.class));

            @SuppressWarnings({"rawtypes", "unchecked"})
            MockedStatic<ClientSessionCode> codes = Mockito.mockStatic(ClientSessionCode.class);
            try (codes) {
                codes.when(() -> ClientSessionCode.getClientSession(
                                anyString(), anyString(), any(), any(), any(), any(), any()))
                        .thenReturn(authSession);

                Method generate = endpoint.getClass()
                        .getDeclaredMethod("generateTokenRequest", String.class);
                generate.setAccessible(true);
                SimpleHttpRequest tokenRequest = (SimpleHttpRequest) generate.invoke(endpoint, "the-authorization-code");
                tokenRequest.asString();
            } catch (ReflectiveOperationException | java.io.IOException e) {
                throw new AssertionError(e);
            }

            assertThat(kickToken.lastRequest().method()).isEqualTo("POST");
            return kickToken.lastRequest().formParams();
        }

        private AuthenticationSessionModel authSessionHolding(String codeVerifier) {
            AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
            when(authSession.getClientNote("BROKER_CODE_CHALLENGE")).thenReturn(codeVerifier);
            return authSession;
        }

        @Test
        void sendsAnAuthorizationCodeGrant() {
            Map<String, String> form = exchange("state-value.tab-id.YXBwLWNsaWVudA",
                    authSessionHolding("the-code-verifier"));

            assertThat(form).containsEntry("grant_type", "authorization_code");
            assertThat(form).containsEntry("code", "the-authorization-code");
        }

        @Test
        @DisplayName("uses the standard Keycloak broker callback URI as redirect_uri")
        void sendsTheBrokerCallbackRedirectUri() {
            Map<String, String> form = exchange("state-value.tab-id.YXBwLWNsaWVudA",
                    authSessionHolding("the-code-verifier"));

            // Must match byte for byte what was sent on the authorization request and what is
            // registered on the Kick application, or Kick rejects the exchange.
            assertThat(form).containsEntry("redirect_uri", REDIRECT_URI);
        }

        @Test
        @DisplayName("replays the PKCE code_verifier stored during the authorization request")
        void sendsTheCodeVerifier() {
            Map<String, String> form = exchange("state-value.tab-id.YXBwLWNsaWVudA",
                    authSessionHolding("the-code-verifier"));

            assertThat(form).containsEntry("code_verifier", "the-code-verifier");
        }

        @Test
        @DisplayName("authenticates the client with client_secret_post, as Kick requires")
        void sendsClientCredentialsInTheBody() {
            Map<String, String> form = exchange("state-value.tab-id.YXBwLWNsaWVudA",
                    authSessionHolding("the-code-verifier"));

            assertThat(form).containsEntry("client_id", CLIENT_ID);
            assertThat(form).containsEntry("client_secret", CLIENT_SECRET);
            assertThat(kickToken.lastRequest().header("Authorization"))
                    .as("credentials belong in the body for client_secret_post, not in a Basic header")
                    .isNull();
        }

        @Test
        void carriesExactlyTheExpectedParameters() {
            Map<String, String> form = exchange("state-value.tab-id.YXBwLWNsaWVudA",
                    authSessionHolding("the-code-verifier"));

            assertThat(form).containsOnlyKeys(
                    "code", "redirect_uri", "grant_type", "code_verifier", "client_id", "client_secret");
        }

        @Test
        void postsAsFormUrlEncoded() {
            exchange("state-value.tab-id.YXBwLWNsaWVudA", authSessionHolding("the-code-verifier"));

            assertThat(kickToken.lastRequest().header("Content-Type"))
                    .startsWith("application/x-www-form-urlencoded");
        }
    }
}
