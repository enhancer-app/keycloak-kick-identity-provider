/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import io.github.enhancerapp.keycloak.kick.KickProfileException.Reason;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class KickProfileParserTest {

    private static Reason reasonOf(String json) {
        KickProfileException e = catchThrowableOfType(KickProfileException.class, () -> KickProfileParser.parse(json));
        assertThat(e).as("expected parsing to be rejected for: %s", json).isNotNull();
        return e.getReason();
    }

    @Nested
    @DisplayName("valid profiles")
    class ValidProfiles {

        @Test
        void parsesAFullyPopulatedProfile() {
            KickProfile profile = KickProfileParser.parse("""
                    {"data":[{"user_id":123,"name":"streamer","email":"user@example.com",
                              "profile_picture":"https://files.kick.com/images/user/123/avatar.png"}]}""");

            assertThat(profile.userId()).isEqualTo("123");
            assertThat(profile.name()).isEqualTo("streamer");
            assertThat(profile.email()).isEqualTo("user@example.com");
            assertThat(profile.profilePicture())
                    .isEqualTo("https://files.kick.com/images/user/123/avatar.png");
        }

        @Test
        void requiresNothingBeyondUserId() {
            KickProfile profile = KickProfileParser.parse("{\"data\":[{\"user_id\":1}]}");

            assertThat(profile.userId()).isEqualTo("1");
            assertThat(profile.name()).isNull();
            assertThat(profile.email()).isNull();
            assertThat(profile.profilePicture()).isNull();
        }

        @Test
        void ignoresUnknownFieldsSoUpstreamAdditionsDoNotBreakLogin() {
            KickProfile profile = KickProfileParser.parse(
                    "{\"message\":\"OK\",\"data\":[{\"user_id\":7,\"channel_slug\":\"x\",\"nested\":{\"a\":1}}]}");

            assertThat(profile.userId()).isEqualTo("7");
        }

        @Test
        void usesOnlyTheFirstEntryWhenKickReturnsSeveral() {
            KickProfile profile = KickProfileParser.parse(
                    "{\"data\":[{\"user_id\":11,\"name\":\"first\"},{\"user_id\":22,\"name\":\"second\"}]}");

            assertThat(profile.userId()).isEqualTo("11");
            assertThat(profile.name()).isEqualTo("first");
        }

        @Test
        void acceptsAUserIdSentAsANumericString() {
            // Kick has returned the id as both a JSON number and a string; both must key the
            // same federated identity, otherwise an upstream representation change would orphan
            // every existing link.
            assertThat(KickProfileParser.parse("{\"data\":[{\"user_id\":\"456\"}]}").userId())
                    .isEqualTo("456");
        }

        @Test
        void acceptsAUserIdBeyondTheRangeOfAnInt() {
            assertThat(KickProfileParser.parse("{\"data\":[{\"user_id\":9007199254740993}]}").userId())
                    .isEqualTo("9007199254740993");
        }

        @Test
        void trimsSurroundingWhitespace() {
            KickProfile profile = KickProfileParser.parse(
                    "{\"data\":[{\"user_id\":\" 5 \",\"name\":\"  spaced  \",\"email\":\" a@b.example \"}]}");

            assertThat(profile.userId()).isEqualTo("5");
            assertThat(profile.name()).isEqualTo("spaced");
            assertThat(profile.email()).isEqualTo("a@b.example");
        }

        @Test
        void treatsBlankTextAsAbsent() {
            KickProfile profile = KickProfileParser.parse(
                    "{\"data\":[{\"user_id\":5,\"name\":\"   \",\"email\":\"\",\"profile_picture\":\"  \"}]}");

            assertThat(profile.name()).isNull();
            assertThat(profile.email()).isNull();
            assertThat(profile.profilePicture()).isNull();
        }

        @Test
        void treatsExplicitNullsAsAbsent() {
            KickProfile profile = KickProfileParser.parse(
                    "{\"data\":[{\"user_id\":5,\"name\":null,\"email\":null,\"profile_picture\":null}]}");

            assertThat(profile.name()).isNull();
            assertThat(profile.email()).isNull();
            assertThat(profile.profilePicture()).isNull();
        }

        @Test
        void capsOverlongTextSoAHostileUpstreamCannotFloodTheUserStore() {
            String huge = "n".repeat(5000);
            KickProfile profile = KickProfileParser.parse(
                    "{\"data\":[{\"user_id\":5,\"name\":\"" + huge + "\"}]}");

            assertThat(profile.name()).hasSize(512);
        }
    }

    @Nested
    @DisplayName("profile picture handling")
    class ProfilePicture {

        @ParameterizedTest
        @ValueSource(strings = {
            "https://files.kick.com/a.png",
            "http://files.kick.com/a.png",
            "https://files.kick.com/a.png?v=2"
        })
        void keepsAbsoluteHttpUrls(String url) {
            assertThat(parsePicture(url)).isEqualTo(url);
        }

        @ParameterizedTest
        @DisplayName("drops anything that is not an absolute http(s) URL")
        @ValueSource(strings = {
            "javascript:alert(1)",
            "data:image/png;base64,AAAA",
            "file:///etc/passwd",
            "/relative/avatar.png",
            "not a url at all",
            "https://",
            "ftp://files.kick.com/a.png"
        })
        void dropsUnsafeOrRelativeValues(String url) {
            // A rejected avatar must not fail the login; it is optional decoration. But it must
            // never be persisted, because a stored javascript:/data: URL becomes a stored-XSS
            // primitive in any theme or downstream app that renders the attribute.
            assertThat(parsePicture(url)).isNull();
        }

        private String parsePicture(String url) {
            String escaped = url.replace("\\", "\\\\").replace("\"", "\\\"");
            return KickProfileParser
                    .parse("{\"data\":[{\"user_id\":1,\"profile_picture\":\"" + escaped + "\"}]}")
                    .profilePicture();
        }
    }

    @Nested
    @DisplayName("malformed documents")
    class Malformed {

        @ParameterizedTest
        @ValueSource(strings = {
            "",
            "   ",
            "not json",
            "{",
            "{\"data\": [",
            "[]",
            "\"a string\"",
            "42",
            "null"
        })
        void rejectsBodiesThatAreNotAJsonObject(String body) {
            assertThat(reasonOf(body)).isEqualTo(Reason.MALFORMED_JSON);
        }

        @Test
        void rejectsANullBody() {
            assertThatThrownBy(() -> KickProfileParser.parse((String) null))
                    .isInstanceOf(KickProfileException.class);
        }

        @Test
        void rejectsANullNode() {
            assertThat(catchThrowableOfType(KickProfileException.class,
                    () -> KickProfileParser.parse((com.fasterxml.jackson.databind.JsonNode) null))
                    .getReason()).isEqualTo(Reason.MALFORMED_JSON);
        }
    }

    @Nested
    @DisplayName("data envelope")
    class DataEnvelope {

        @Test
        void rejectsAMissingDataProperty() {
            assertThat(reasonOf("{\"message\":\"OK\"}")).isEqualTo(Reason.MISSING_DATA);
        }

        @Test
        void rejectsANullDataProperty() {
            assertThat(reasonOf("{\"data\":null}")).isEqualTo(Reason.MISSING_DATA);
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "{\"data\":{}}",
            "{\"data\":\"streamer\"}",
            "{\"data\":5}",
            "{\"data\":true}"
        })
        void rejectsADataPropertyThatIsNotAnArray(String body) {
            assertThat(reasonOf(body)).isEqualTo(Reason.DATA_NOT_ARRAY);
        }

        @Test
        void rejectsAnEmptyDataArray() {
            // Kick answers 200 with an empty array when the token is valid but carries no user
            // context. Coercing that into an anonymous identity would authenticate nobody as
            // somebody, so it must fail closed.
            assertThat(reasonOf("{\"data\":[]}")).isEqualTo(Reason.EMPTY_DATA);
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "{\"data\":[null]}",
            "{\"data\":[\"streamer\"]}",
            "{\"data\":[123]}",
            "{\"data\":[[]]}"
        })
        void rejectsAFirstEntryThatIsNotAnObject(String body) {
            assertThat(reasonOf(body)).isEqualTo(Reason.ENTRY_NOT_OBJECT);
        }
    }

    @Nested
    @DisplayName("user_id validation")
    class UserId {

        @ParameterizedTest
        @ValueSource(strings = {
            "{\"data\":[{\"name\":\"streamer\"}]}",
            "{\"data\":[{\"user_id\":null}]}",
            "{\"data\":[{\"user_id\":\"\"}]}",
            "{\"data\":[{\"user_id\":\"   \"}]}",
            "{\"data\":[{\"userId\":123}]}"
        })
        void rejectsAnAbsentUserId(String body) {
            assertThat(reasonOf(body)).isEqualTo(Reason.MISSING_USER_ID);
        }

        @ParameterizedTest
        @DisplayName("rejects user_id values that are not a non-negative integer")
        @ValueSource(strings = {
            "{\"data\":[{\"user_id\":{}}]}",
            "{\"data\":[{\"user_id\":[1]}]}",
            "{\"data\":[{\"user_id\":true}]}",
            "{\"data\":[{\"user_id\":1.5}]}",
            "{\"data\":[{\"user_id\":\"12a\"}]}",
            "{\"data\":[{\"user_id\":\"abc\"}]}",
            "{\"data\":[{\"user_id\":\"1 2\"}]}",
            "{\"data\":[{\"user_id\":-5}]}",
            "{\"data\":[{\"user_id\":\"-5\"}]}"
        })
        void rejectsAnUnusableUserId(String body) {
            // Anything coerced here would become the federated identity subject. A wrong or
            // unstable subject either orphans an existing link or merges two Kick accounts onto
            // one Keycloak user, so every ambiguous representation is refused.
            assertThat(reasonOf(body)).isEqualTo(Reason.INVALID_USER_ID);
        }
    }

    @Nested
    @DisplayName("failure messages")
    class FailureMessages {

        @Test
        void neverEchoTheOffendingPayload() {
            String secretish = "SUPER_SECRET_VALUE_9f3c";
            KickProfileException e = catchThrowableOfType(KickProfileException.class,
                    () -> KickProfileParser.parse("{\"data\":[{\"user_id\":{\"leak\":\"" + secretish + "\"}}]}"));

            assertThat(e.getMessage()).doesNotContain(secretish);
            assertThat(e.getMessage()).isEqualTo(Reason.INVALID_USER_ID.getMessage());
        }

        @Test
        void carryNoCauseThatCouldReintroduceThePayload() {
            KickProfileException e = catchThrowableOfType(KickProfileException.class,
                    () -> KickProfileParser.parse("{\"data\": [ SECRET_TOKEN_abc "));

            assertThat(e.getCause())
                    .as("a chained Jackson cause would carry a fragment of the payload into the log")
                    .isNull();
            assertThat(e.getMessage()).doesNotContain("SECRET_TOKEN_abc");
        }
    }
}
