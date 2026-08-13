/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

import java.io.IOException;

import org.apache.http.client.config.RequestConfig;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Kick (kick.com) social identity provider.
 *
 * <p>Implements the Kick OAuth 2.1 authorization code flow. The authorization request, PKCE
 * handling and the code-for-token exchange are performed by
 * {@link AbstractOAuth2IdentityProvider}; this class pins the configuration (endpoints, PKCE
 * S256) and owns retrieval and validation of the Kick user profile.
 *
 * <h2>Logging policy</h2>
 * No method in this class passes an authorization code, access token, refresh token, client
 * secret or a response body to the logger. Failures are reported with the HTTP status code and a
 * constant reason string only. {@code KickLogRedactionTest} enforces this.
 */
public class KickIdentityProvider extends AbstractOAuth2IdentityProvider<KickIdentityProviderConfig>
        implements SocialIdentityProvider<KickIdentityProviderConfig> {

    static final Logger LOG = Logger.getLogger(KickIdentityProvider.class);

    /** Minimum scope required to read the authenticated user's Kick profile. */
    public static final String DEFAULT_SCOPE = "user:read";

    /**
     * Bounded timeouts for the profile call.
     *
     * <p>Keycloak's shared HTTP client has server-wide defaults that a deployment may raise. A
     * slow Kick response must not pin a Keycloak request thread for the duration of a login,
     * so the per-request budget is capped here regardless of the global setting.
     */
    static final int CONNECT_TIMEOUT_MILLIS = 5_000;
    static final int SOCKET_TIMEOUT_MILLIS = 5_000;
    static final int CONNECTION_REQUEST_TIMEOUT_MILLIS = 5_000;

    /**
     * Hard cap on the profile response body. The document is a handful of fields; anything
     * larger is either a misdirected endpoint or an attempt to exhaust heap.
     */
    static final long MAX_PROFILE_RESPONSE_BYTES = 256L * 1024L;

    private static final RequestConfig REQUEST_CONFIG = RequestConfig.custom()
            .setConnectTimeout(CONNECT_TIMEOUT_MILLIS)
            .setSocketTimeout(SOCKET_TIMEOUT_MILLIS)
            .setConnectionRequestTimeout(CONNECTION_REQUEST_TIMEOUT_MILLIS)
            .build();

    /** Constant, payload-free message used for every profile retrieval failure. */
    static final String PROFILE_FAILURE_MESSAGE =
            "Could not retrieve the Kick user profile. See the server log for the failure reason.";

    public KickIdentityProvider(KeycloakSession session, KickIdentityProviderConfig config) {
        super(session, config);
        config.applyFixedSettings();
        if (config.isStoreToken() == null) {
            // Keep the standard Keycloak behavior, but make its default explicit for a newly
            // created provider. Token storage remains an administrator-controlled checkbox.
            config.setStoreToken(false);
        }
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    /**
     * Extracts the access token without delegating to the base implementation's error path.
     *
     * <p>In Keycloak 26.5 the base implementation includes the entire remote token response in
     * the exception it throws when {@code access_token} is absent. Token responses can contain
     * authorization codes, refresh tokens, client-error detail or echoed credentials, so that
     * behavior violates this provider's no-secret-logging contract. Kick uses JSON responses;
     * accepting only a non-blank textual JSON {@code access_token} is intentionally fail-closed.
     */
    @Override
    public BrokeredIdentityContext getFederatedIdentity(String tokenResponse) {
        final String accessToken;
        try {
            JsonNode response = mapper.readTree(tokenResponse);
            JsonNode accessTokenNode = response == null ? null : response.get(OAUTH2_PARAMETER_ACCESS_TOKEN);
            if (accessTokenNode == null || !accessTokenNode.isTextual() || accessTokenNode.asText().isBlank()) {
                LOG.warn("Kick token response did not contain an access token.");
                throw new IdentityBrokerException(PROFILE_FAILURE_MESSAGE);
            }
            accessToken = accessTokenNode.asText();
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            // Do not chain Jackson's exception: it may embed a response fragment in its message.
            LOG.warn("Kick token response was not valid JSON.");
            throw new IdentityBrokerException(PROFILE_FAILURE_MESSAGE);
        }

        // The base implementation now sees a known-good access_token. Delegate to retain its
        // standard opt-in token-storage handling (including expiration metadata and refresh
        // tokens) without ever reaching its payload-echoing missing-token error path.
        return super.getFederatedIdentity(tokenResponse);
    }

    /**
     * Base URL used for the profile call.
     *
     * <p>Overridable only so tests can point the call at a local stub server; production code
     * always resolves to the pinned {@link KickEndpoints#PROFILE_URL}.
     */
    protected String getProfileUrl() {
        return KickEndpoints.PROFILE_URL;
    }

    /**
     * Per-request timeout budget. Overridable so tests can exercise timeout handling without
     * waiting out the production budget.
     */
    protected RequestConfig getRequestConfig() {
        return REQUEST_CONFIG;
    }

    /**
     * HTTP entry point, isolated as a seam so tests can supply their own client without
     * resorting to static mocking.
     */
    protected SimpleHttp createHttp() {
        return SimpleHttp.create(session)
                .withRequestConfig(getRequestConfig())
                .withMaxConsumedResponseSize(MAX_PROFILE_RESPONSE_BYTES);
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            LOG.warn("Kick token response did not contain an access token.");
            throw new IdentityBrokerException(PROFILE_FAILURE_MESSAGE);
        }

        final JsonNode profileJson;
        try (SimpleHttpResponse response = createHttp()
                .doGet(getProfileUrl())
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .asResponse()) {

            int status = response.getStatus();
            if (status < 200 || status > 299) {
                // Status only. The body may echo the bearer token or other sensitive detail.
                LOG.warnf("Kick profile endpoint returned HTTP %d.", status);
                throw new IdentityBrokerException(PROFILE_FAILURE_MESSAGE);
            }

            try {
                profileJson = response.asJson();
            } catch (IOException e) {
                LOG.warn("Kick profile endpoint returned a body that is not valid JSON.");
                throw new IdentityBrokerException(PROFILE_FAILURE_MESSAGE);
            }
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            // Message and stack trace of the cause are dropped: an HTTP client exception can
            // contain the request URI including any query string.
            LOG.warnf("Kick profile endpoint could not be reached (%s).", e.getClass().getSimpleName());
            throw new IdentityBrokerException(PROFILE_FAILURE_MESSAGE);
        }

        return extractIdentityFromProfile(null, profileJson);
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profileJson) {
        final KickProfile profile;
        try {
            profile = KickProfileParser.parse(profileJson);
        } catch (KickProfileException e) {
            LOG.warnf("Rejected Kick profile response: %s.", e.getReason().name());
            throw new IdentityBrokerException(PROFILE_FAILURE_MESSAGE);
        }

        KickIdentityProviderConfig config = getConfig();

        // The Kick user_id is the sole subject. Name, e-mail, channel and avatar are all mutable
        // upstream and must never key the federated identity link.
        BrokeredIdentityContext user = new BrokeredIdentityContext(profile.userId(), config);
        user.setUsername(config.getUsernameStrategy().resolve(profile, config.getUsernamePrefix()));
        user.setIdp(this);

        // First and last name are deliberately left unset. Kick returns a single free-form display
        // name with no given/family split, and BrokeredIdentityContext#setName would fabricate one
        // by splitting on the last space -- turning "Foo Bar Baz" into firstName="Foo Bar",
        // lastName="Baz". The current Kick name is instead exposed as provider profile data below,
        // where an administrator can map it deliberately. See README "Profile field mapping".

        if (config.isImportEmail()) {
            user.setEmail(profile.email());
        }
        if (config.isStoreAvatar() && profile.profilePicture() != null) {
            user.setUserAttribute(config.getAvatarAttribute(), profile.profilePicture());
        }

        // Makes the raw profile document available to declarative attribute mappers.
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profileJson, config.getAlias());

        return user;
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
        applyAvatar(user, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
        // IMPORT sync mode means "populate once"; re-writing the attribute on every login would
        // silently override a value an administrator or the user has since changed.
        if (getConfig().getSyncMode() == IdentityProviderSyncMode.FORCE) {
            applyAvatar(user, context);
        }
    }

    private void applyAvatar(UserModel user, BrokeredIdentityContext context) {
        KickIdentityProviderConfig config = getConfig();
        if (!config.isStoreAvatar()) {
            return;
        }
        String attribute = config.getAvatarAttribute();
        String value = context.getUserAttribute(attribute);
        if (value == null || value.isBlank()) {
            user.removeAttribute(attribute);
        } else {
            user.setSingleAttribute(attribute, value);
        }
    }
}
