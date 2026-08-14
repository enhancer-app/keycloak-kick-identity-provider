/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

import java.util.List;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * Registers Kick as a first-class social identity provider.
 *
 * <p>Discovered by Keycloak through
 * {@code META-INF/services/org.keycloak.broker.social.SocialIdentityProviderFactory}, which is
 * what makes it appear in the Admin Console's social provider list rather than requiring a
 * generic OpenID Connect / OAuth 2 provider to be configured by hand.
 */
public class KickIdentityProviderFactory extends AbstractIdentityProviderFactory<KickIdentityProvider>
        implements SocialIdentityProviderFactory<KickIdentityProvider> {

    /** Provider id; also the default alias and the broker callback path segment. */
    public static final String PROVIDER_ID = "kick";

    @Override
    public String getName() {
        return "Kick";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public KickIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new KickIdentityProvider(session, new KickIdentityProviderConfig(model));
    }

    @Override
    public KickIdentityProviderConfig createConfig() {
        KickIdentityProviderConfig config = new KickIdentityProviderConfig();
        config.applyDefaults();
        return config;
    }

    /**
     * Kick-specific settings rendered by the Admin Console in addition to the standard social
     * provider fields (client id, client secret, display name, scopes, sync mode, store tokens).
     *
     * <p>Authorization, token and profile URLs are deliberately absent: they are pinned in
     * {@link KickEndpoints} and cannot be overridden.
     */
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property().name("authorizationUrl").label("Authorization URL")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(KickEndpoints.AUTHORIZATION_URL).add()
                .property().name("tokenUrl").label("Token URL")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(KickEndpoints.TOKEN_URL).add()
                .property().name("userInfoUrl").label("Profile URL")
                    .type(ProviderConfigProperty.STRING_TYPE).defaultValue(KickEndpoints.PROFILE_URL).add()
                .property()
                    .name(KickIdentityProviderConfig.USERNAME_STRATEGY)
                    .label("Username strategy")
                    .helpText("How the Keycloak username is proposed on first login. "
                            + "'" + KickUsernameStrategy.STABLE_ID_PREFIX.getConfigValue() + "' derives it "
                            + "from the immutable Kick user id and never collides. "
                            + "'" + KickUsernameStrategy.PROVIDER_USERNAME.getConfigValue() + "' uses the "
                            + "current Kick display name, which is mutable and may collide with an "
                            + "existing user. The federated identity is keyed on the Kick user id either way.")
                    .type(ProviderConfigProperty.LIST_TYPE)
                    .options(KickUsernameStrategy.STABLE_ID_PREFIX.getConfigValue(),
                            KickUsernameStrategy.PROVIDER_USERNAME.getConfigValue())
                    .defaultValue(KickUsernameStrategy.STABLE_ID_PREFIX.getConfigValue())
                    .add()
                .property()
                    .name(KickIdentityProviderConfig.USERNAME_PREFIX)
                    .label("Username prefix")
                    .helpText("Prefix used by the '" + KickUsernameStrategy.STABLE_ID_PREFIX.getConfigValue()
                            + "' strategy, producing usernames such as 'kick-123'. "
                            + "Left blank, '" + KickUsernameStrategy.DEFAULT_PREFIX + "' is used.")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .defaultValue(KickUsernameStrategy.DEFAULT_PREFIX)
                    .add()
                .build();
    }
}
