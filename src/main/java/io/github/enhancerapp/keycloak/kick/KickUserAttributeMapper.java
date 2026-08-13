/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;

/**
 * Declarative mapper from any field of the Kick profile document to a Keycloak user attribute.
 *
 * <p>Lets an administrator map fields this provider does not surface itself (or map them to a
 * different attribute name) without writing code, using JSON paths such as
 * {@code data[0].profile_picture}. Honours the mapper sync mode, so FORCE-mode realms keep the
 * mapped attributes fresh on every login.
 */
public class KickUserAttributeMapper extends AbstractJsonUserAttributeMapper {

    public static final String PROVIDER_ID = "kick-user-attribute-mapper";

    private static final String[] COMPATIBLE_PROVIDERS = new String[] {
        KickIdentityProviderFactory.PROVIDER_ID
    };

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS.clone();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
