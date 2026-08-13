/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick.support;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.Optional;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

import org.apache.http.impl.client.HttpClients;
import org.keycloak.common.ClientConnection;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.vault.VaultStringSecret;
import org.keycloak.vault.VaultTranscriber;

/**
 * Minimal {@link KeycloakSession} stand-ins for exercising broker code outside a running server.
 *
 * <p>Only the collaborators Keycloak's broker code actually touches during an authorization or
 * token request are stubbed. A real Apache HTTP client is wired in, so requests genuinely travel
 * over a socket to a local stub server rather than being intercepted -- a test that asserts "the
 * token request carried a code_verifier" therefore asserts what goes on the wire.
 *
 * <p>Deep stubs are deliberately avoided: {@code KeycloakSession#getProvider} is generic, and a
 * deep stub resolves its return type to the erased {@code Provider} interface, which then fails
 * to cast at the call site.
 */
public final class KeycloakStubs {

    /** The stubbed session together with the collaborators a test may want to refine. */
    public record Session(KeycloakSession session,
                          KeycloakContext context,
                          KeycloakUriInfo uriInfo,
                          MultivaluedMap<String, String> queryParameters) {
    }

    private KeycloakStubs() {
        throw new AssertionError("no instances");
    }

    /**
     * @param baseUri the realm base URI, from which Keycloak derives the broker callback URI
     * @param realm   the realm the request runs in; may be {@code null} when unused
     */
    public static Session session(URI baseUri, RealmModel realm) {
        KeycloakSession session = mock(KeycloakSession.class);

        HttpClientProvider httpClientProvider = mock(HttpClientProvider.class);
        when(httpClientProvider.getHttpClient()).thenReturn(HttpClients.createDefault());
        when(httpClientProvider.getMaxConsumedResponseSize())
                .thenReturn(HttpClientProvider.DEFAULT_MAX_CONSUMED_RESPONSE_SIZE);
        when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);

        // The broker resolves the client secret through the vault transcriber. An empty Optional
        // means "not a vault reference", making Keycloak fall back to the literal configured value.
        VaultStringSecret emptySecret = mock(VaultStringSecret.class);
        when(emptySecret.get()).thenReturn(Optional.empty());
        VaultTranscriber vault = mock(VaultTranscriber.class);
        when(vault.getStringSecret(anyString())).thenReturn(emptySecret);
        when(session.vault()).thenReturn(vault);

        MultivaluedMap<String, String> queryParameters = new MultivaluedHashMap<>();
        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        when(uriInfo.getBaseUri()).thenReturn(baseUri);
        when(uriInfo.getRequestUri()).thenReturn(baseUri);
        when(uriInfo.getQueryParameters()).thenReturn(queryParameters);

        KeycloakContext context = mock(KeycloakContext.class);
        when(context.getUri()).thenReturn(uriInfo);
        when(context.getRealm()).thenReturn(realm);
        when(context.getConnection()).thenReturn(mock(ClientConnection.class));
        when(context.getHttpRequest()).thenReturn(mock(HttpRequest.class));
        when(session.getContext()).thenReturn(context);

        return new Session(session, context, uriInfo, queryParameters);
    }

    public static Session session(URI baseUri) {
        return session(baseUri, null);
    }

    /** @return a realm whose only meaningful property is its name. */
    public static RealmModel realm(String name) {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn(name);
        return realm;
    }
}
