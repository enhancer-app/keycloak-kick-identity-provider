/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

import java.util.Objects;

/**
 * Immutable, validated view of a single Kick user record.
 *
 * @param userId          the stable Kick {@code user_id}; never {@code null} or blank. This is the
 *                        only value used as the brokered identity subject.
 * @param name            the current Kick display name, or {@code null} when absent/blank. Mutable
 *                        upstream; never used as an identity key.
 * @param email           the Kick account e-mail, or {@code null} when absent/blank. Optional
 *                        profile information only; never used as an identity key.
 * @param profilePicture  an absolute {@code http}/{@code https} avatar URL, or {@code null} when
 *                        absent, blank or not an acceptable URL.
 */
public record KickProfile(String userId, String name, String email, String profilePicture) {

    public KickProfile {
        Objects.requireNonNull(userId, "userId");
        if (userId.isBlank()) {
            throw new IllegalArgumentException("userId must not be blank");
        }
    }
}
