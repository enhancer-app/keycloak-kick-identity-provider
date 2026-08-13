/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

import java.util.Locale;

/**
 * Determines the username proposed to Keycloak's first-broker-login flow.
 *
 * <p>The username is a convenience label only. The brokered identity is always keyed on
 * {@link KickProfile#userId()}, so changing this setting never re-keys or duplicates an
 * existing federated identity link.
 */
public enum KickUsernameStrategy {

    /**
     * {@code <prefix><user_id>}, e.g. {@code kick-123}. Default, because it is derived purely
     * from the immutable Kick subject and therefore never collides with a renamed account.
     */
    STABLE_ID_PREFIX("stable-id-prefix"),

    /**
     * The current Kick display name, falling back to {@link #STABLE_ID_PREFIX} when Kick returns
     * no usable name. Kick names are mutable and not guaranteed unique across time, so this may
     * collide with an existing local user and trigger the account-link flow.
     */
    PROVIDER_USERNAME("provider-username");

    /** Default prefix applied by {@link #STABLE_ID_PREFIX}. */
    public static final String DEFAULT_PREFIX = "kick-";

    private final String configValue;

    KickUsernameStrategy(String configValue) {
        this.configValue = configValue;
    }

    /** @return the value stored in the identity provider configuration. */
    public String getConfigValue() {
        return configValue;
    }

    /**
     * Resolves a configuration value, tolerating {@code null}, blank and unknown input.
     *
     * <p>An unrecognised value falls back to {@link #STABLE_ID_PREFIX} rather than failing the
     * login: a typo in configuration must not lock users out of the realm.
     */
    public static KickUsernameStrategy fromConfigValue(String value) {
        if (value != null) {
            String normalized = value.trim().toLowerCase(Locale.ROOT);
            for (KickUsernameStrategy strategy : values()) {
                if (strategy.configValue.equals(normalized) || strategy.name().equalsIgnoreCase(normalized)) {
                    return strategy;
                }
            }
        }
        return STABLE_ID_PREFIX;
    }

    /**
     * Builds the username for the given profile.
     *
     * @param profile validated Kick profile; must not be {@code null}
     * @param prefix  prefix for {@link #STABLE_ID_PREFIX}; {@code null}/blank means
     *                {@link #DEFAULT_PREFIX}
     * @return a non-blank username
     */
    public String resolve(KickProfile profile, String prefix) {
        if (profile == null) {
            throw new IllegalArgumentException("profile must not be null");
        }
        if (this == PROVIDER_USERNAME) {
            String name = profile.name();
            if (name != null && !name.isBlank()) {
                return name.trim();
            }
        }
        return normalizePrefix(prefix) + profile.userId();
    }

    private static String normalizePrefix(String prefix) {
        if (prefix == null) {
            return DEFAULT_PREFIX;
        }
        String trimmed = prefix.trim();
        return trimmed.isEmpty() ? DEFAULT_PREFIX : trimmed;
    }
}
