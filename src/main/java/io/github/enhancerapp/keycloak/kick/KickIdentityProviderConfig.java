/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

/**
 * Typed accessors for the Kick provider configuration.
 *
 * <p>Beyond the standard OAuth 2 broker settings this adds the Kick-specific toggles. It also
 * owns {@link #applyFixedSettings()}, which pins the security-relevant parts of the
 * configuration so that neither a hand-crafted admin REST call nor a partial realm import can
 * weaken them.
 */
public class KickIdentityProviderConfig extends OAuth2IdentityProviderConfig {

    private static final long serialVersionUID = 1L;

    /** Import the Kick e-mail into the Keycloak user profile. Disabled by default. */
    public static final String IMPORT_EMAIL = "importEmail";

    /** Store the Kick avatar URL as a user attribute. Enabled by default. */
    public static final String STORE_AVATAR = "storeAvatar";

    /** Name of the user attribute receiving the avatar URL. */
    public static final String AVATAR_ATTRIBUTE = "avatarAttribute";

    /** Attribute name used when {@link #AVATAR_ATTRIBUTE} is unset. */
    public static final String DEFAULT_AVATAR_ATTRIBUTE = "kick_profile_picture";

    /** Username derivation strategy; see {@link KickUsernameStrategy}. */
    public static final String USERNAME_STRATEGY = "usernameStrategy";

    /** Prefix used by {@link KickUsernameStrategy#STABLE_ID_PREFIX}. */
    public static final String USERNAME_PREFIX = "usernamePrefix";

    public KickIdentityProviderConfig() {
        super();
    }

    public KickIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    /**
     * Forces every setting this provider refuses to delegate to the administrator.
     *
     * <p>Called from the provider constructor on every instantiation, so the values are
     * re-asserted on each authentication rather than only at creation time.
     *
     * <ul>
     *   <li>Endpoint URLs are reset to {@link KickEndpoints}. Kick is a single, known deployment;
     *       an overridable endpoint would let a realm administrator forward client credentials and
     *       authorization codes to an arbitrary host, and would make the Keycloak server issue
     *       requests to attacker-chosen URLs.</li>
     *   <li>PKCE is forced on with {@code S256}. Kick requires PKCE, and {@code plain} offers no
     *       protection against code interception.</li>
     *   <li>A default scope of {@code user:read} is applied when the administrator left the field
     *       empty, because Kick rejects an authorization request with no scope.</li>
     * </ul>
     */
    public void applyFixedSettings() {
        setAuthorizationUrl(KickEndpoints.AUTHORIZATION_URL);
        setTokenUrl(KickEndpoints.TOKEN_URL);
        setUserInfoUrl(KickEndpoints.PROFILE_URL);

        setPkceEnabled(true);
        setPkceMethod(OAuth2Constants.PKCE_METHOD_S256);

        if (getDefaultScope() == null || getDefaultScope().isBlank()) {
            setDefaultScope(KickIdentityProvider.DEFAULT_SCOPE);
        }
    }

    public boolean isImportEmail() {
        return getBoolean(IMPORT_EMAIL, false);
    }

    public void setImportEmail(boolean value) {
        getConfig().put(IMPORT_EMAIL, String.valueOf(value));
    }

    public boolean isStoreAvatar() {
        return getBoolean(STORE_AVATAR, true);
    }

    public void setStoreAvatar(boolean value) {
        getConfig().put(STORE_AVATAR, String.valueOf(value));
    }

    public String getAvatarAttribute() {
        String value = getConfig().get(AVATAR_ATTRIBUTE);
        return (value == null || value.isBlank()) ? DEFAULT_AVATAR_ATTRIBUTE : value.trim();
    }

    public void setAvatarAttribute(String value) {
        getConfig().put(AVATAR_ATTRIBUTE, value);
    }

    public KickUsernameStrategy getUsernameStrategy() {
        return KickUsernameStrategy.fromConfigValue(getConfig().get(USERNAME_STRATEGY));
    }

    public void setUsernameStrategy(KickUsernameStrategy strategy) {
        getConfig().put(USERNAME_STRATEGY, strategy.getConfigValue());
    }

    public String getUsernamePrefix() {
        String value = getConfig().get(USERNAME_PREFIX);
        return (value == null || value.isBlank()) ? KickUsernameStrategy.DEFAULT_PREFIX : value.trim();
    }

    public void setUsernamePrefix(String value) {
        getConfig().put(USERNAME_PREFIX, value);
    }

    /**
     * Reads a boolean flag, treating an absent or blank entry as {@code defaultValue}.
     *
     * <p>{@code Boolean.parseBoolean} maps every non-{@code "true"} string to {@code false}, which
     * would silently turn an unset "store avatar" flag off even though its documented default is
     * on. Distinguishing "absent" from "explicitly false" is therefore required here.
     */
    private boolean getBoolean(String key, boolean defaultValue) {
        String value = getConfig().get(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        return Boolean.parseBoolean(value.trim());
    }
}
