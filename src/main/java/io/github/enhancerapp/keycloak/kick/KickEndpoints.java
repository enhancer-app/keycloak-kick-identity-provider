/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

/**
 * Upstream Kick endpoints.
 *
 * <p>These values are intentionally compiled in and are <strong>not</strong> exposed as
 * administrator-configurable options. Allowing an administrator to point the broker at an
 * arbitrary host would turn every Keycloak instance into an SSRF gadget and would allow
 * silently redirecting client credentials and authorization codes to a third party.
 *
 * <p>{@link KickIdentityProvider} overwrites any URL found in the persisted provider
 * configuration with these constants on every instantiation.
 */
public final class KickEndpoints {

    /** Kick OAuth 2.1 authorization endpoint. */
    public static final String AUTHORIZATION_URL = "https://id.kick.com/oauth/authorize";

    /** Kick OAuth 2.1 token endpoint. */
    public static final String TOKEN_URL = "https://id.kick.com/oauth/token";

    /** Kick public API endpoint returning the token owner's user record. */
    public static final String PROFILE_URL = "https://api.kick.com/public/v1/users";

    private KickEndpoints() {
        throw new AssertionError("no instances");
    }
}
