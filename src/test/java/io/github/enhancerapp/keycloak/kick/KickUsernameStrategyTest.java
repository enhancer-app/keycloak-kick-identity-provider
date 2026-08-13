/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class KickUsernameStrategyTest {

    private static final KickProfile NAMED = new KickProfile("123", "streamer", null, null);
    private static final KickProfile ANONYMOUS = new KickProfile("123", null, null, null);

    @Test
    void stableIdPrefixUsesTheImmutableKickSubject() {
        assertThat(KickUsernameStrategy.STABLE_ID_PREFIX.resolve(NAMED, "kick-")).isEqualTo("kick-123");
    }

    @Test
    void stableIdPrefixIgnoresTheDisplayName() {
        // The whole point of this strategy: renaming a Kick account must not change the username.
        assertThat(KickUsernameStrategy.STABLE_ID_PREFIX.resolve(NAMED, "kick-"))
                .isEqualTo(KickUsernameStrategy.STABLE_ID_PREFIX.resolve(
                        new KickProfile("123", "renamed", null, null), "kick-"));
    }

    @Test
    void providerUsernameUsesTheCurrentDisplayName() {
        assertThat(KickUsernameStrategy.PROVIDER_USERNAME.resolve(NAMED, "kick-")).isEqualTo("streamer");
    }

    @Test
    void providerUsernameFallsBackToTheStableIdWhenKickReturnsNoName() {
        // Kick omits the name for some accounts. Falling back keeps the login working instead of
        // proposing a blank username that Keycloak would reject.
        assertThat(KickUsernameStrategy.PROVIDER_USERNAME.resolve(ANONYMOUS, "kick-")).isEqualTo("kick-123");
    }

    @Test
    void usesACustomPrefix() {
        assertThat(KickUsernameStrategy.STABLE_ID_PREFIX.resolve(NAMED, "twitch_like_")).isEqualTo("twitch_like_123");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    @DisplayName("a blank prefix means 'not configured' and falls back to the default")
    void blankPrefixFallsBackToDefault(String prefix) {
        assertThat(KickUsernameStrategy.STABLE_ID_PREFIX.resolve(NAMED, prefix)).isEqualTo("kick-123");
    }

    @Test
    void trimsTheConfiguredPrefix() {
        assertThat(KickUsernameStrategy.STABLE_ID_PREFIX.resolve(NAMED, "  kick-  ")).isEqualTo("kick-123");
    }

    @ParameterizedTest
    @ValueSource(strings = {"stable-id-prefix", "STABLE-ID-PREFIX", "  stable-id-prefix  ", "STABLE_ID_PREFIX"})
    void resolvesTheStableIdConfigValueCaseInsensitively(String value) {
        assertThat(KickUsernameStrategy.fromConfigValue(value)).isEqualTo(KickUsernameStrategy.STABLE_ID_PREFIX);
    }

    @ParameterizedTest
    @ValueSource(strings = {"provider-username", "PROVIDER-USERNAME", "PROVIDER_USERNAME"})
    void resolvesTheProviderUsernameConfigValueCaseInsensitively(String value) {
        assertThat(KickUsernameStrategy.fromConfigValue(value)).isEqualTo(KickUsernameStrategy.PROVIDER_USERNAME);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"nonsense", "channel-name"})
    @DisplayName("an unknown or missing strategy falls back to the safe default rather than failing login")
    void unknownConfigValueFallsBackToStableId(String value) {
        // A typo in the identity provider configuration must not lock every user out of the realm.
        assertThat(KickUsernameStrategy.fromConfigValue(value)).isEqualTo(KickUsernameStrategy.STABLE_ID_PREFIX);
    }

    @Test
    void everyStrategyProducesANonBlankUsername() {
        for (KickUsernameStrategy strategy : KickUsernameStrategy.values()) {
            assertThat(strategy.resolve(ANONYMOUS, null)).isNotBlank();
            assertThat(strategy.resolve(NAMED, null)).isNotBlank();
        }
    }

    @Test
    void trimsAProviderUsernameWithSurroundingWhitespace() {
        assertThat(KickUsernameStrategy.PROVIDER_USERNAME.resolve(
                new KickProfile("1", "  spaced  ", null, null), null)).isEqualTo("spaced");
    }
}
