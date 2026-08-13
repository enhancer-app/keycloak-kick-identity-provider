/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.regex.Pattern;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Parses and validates the Kick {@code /public/v1/users} response.
 *
 * <p>The expected shape is:
 * <pre>{@code
 * { "data": [ { "user_id": 123, "name": "streamer",
 *               "email": "user@example.com", "profile_picture": "https://..." } ] }
 * }</pre>
 *
 * <p>This class has no Keycloak, session or HTTP dependency by design: all identity-critical
 * validation is therefore exhaustively unit-testable without a running server. Every rejection
 * path raises a {@link KickProfileException} whose message is a compile-time constant, so no
 * fragment of the remote payload can escape into logs or error pages.
 */
public final class KickProfileParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Kick user ids are non-negative integers. Anything else is not a stable subject we accept. */
    private static final Pattern NUMERIC_ID = Pattern.compile("\\d{1,19}");

    /** Defensive cap so a hostile upstream cannot push unbounded strings into the user store. */
    private static final int MAX_TEXT_LENGTH = 512;

    static final String FIELD_DATA = "data";
    static final String FIELD_USER_ID = "user_id";
    static final String FIELD_NAME = "name";
    static final String FIELD_EMAIL = "email";
    static final String FIELD_PROFILE_PICTURE = "profile_picture";

    private KickProfileParser() {
        throw new AssertionError("no instances");
    }

    /**
     * Parses a raw JSON document.
     *
     * @param json raw response body; may be {@code null}
     * @return the validated profile
     * @throws KickProfileException if the body is not parseable or not a valid Kick profile
     */
    public static KickProfile parse(String json) {
        if (json == null || json.isBlank()) {
            throw new KickProfileException(KickProfileException.Reason.MALFORMED_JSON);
        }
        final JsonNode root;
        try {
            root = MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            // Cause intentionally dropped: Jackson embeds the offending payload in its message.
            throw new KickProfileException(KickProfileException.Reason.MALFORMED_JSON);
        }
        return parse(root);
    }

    /**
     * Validates an already-parsed JSON document.
     *
     * @param root parsed response body; may be {@code null}
     * @return the validated profile
     * @throws KickProfileException if the document is not a valid Kick profile
     */
    public static KickProfile parse(JsonNode root) {
        if (root == null || !root.isObject()) {
            throw new KickProfileException(KickProfileException.Reason.MALFORMED_JSON);
        }

        JsonNode data = root.get(FIELD_DATA);
        if (data == null || data.isNull()) {
            throw new KickProfileException(KickProfileException.Reason.MISSING_DATA);
        }
        if (!data.isArray()) {
            throw new KickProfileException(KickProfileException.Reason.DATA_NOT_ARRAY);
        }
        if (data.isEmpty()) {
            throw new KickProfileException(KickProfileException.Reason.EMPTY_DATA);
        }

        JsonNode entry = data.get(0);
        if (entry == null || !entry.isObject()) {
            throw new KickProfileException(KickProfileException.Reason.ENTRY_NOT_OBJECT);
        }

        String userId = readUserId(entry.get(FIELD_USER_ID));

        return new KickProfile(
                userId,
                readText(entry.get(FIELD_NAME)),
                readText(entry.get(FIELD_EMAIL)),
                readHttpUrl(entry.get(FIELD_PROFILE_PICTURE)));
    }

    /**
     * Extracts the stable subject identifier.
     *
     * <p>Accepts JSON integers and numeric strings (Kick has shipped both over time). Rejects
     * floating point numbers, booleans, objects, arrays and anything non-numeric, because
     * silently coercing those would produce an unstable subject and could collide two distinct
     * Kick accounts onto one Keycloak user.
     */
    private static String readUserId(JsonNode node) {
        if (node == null || node.isNull()) {
            throw new KickProfileException(KickProfileException.Reason.MISSING_USER_ID);
        }
        if (node.isIntegralNumber()) {
            String value = node.asText();
            if (!NUMERIC_ID.matcher(value).matches()) {
                // Negative values land here.
                throw new KickProfileException(KickProfileException.Reason.INVALID_USER_ID);
            }
            return value;
        }
        if (node.isTextual()) {
            String value = node.asText().trim();
            if (value.isEmpty()) {
                throw new KickProfileException(KickProfileException.Reason.MISSING_USER_ID);
            }
            if (!NUMERIC_ID.matcher(value).matches()) {
                throw new KickProfileException(KickProfileException.Reason.INVALID_USER_ID);
            }
            return value;
        }
        throw new KickProfileException(KickProfileException.Reason.INVALID_USER_ID);
    }

    /** @return trimmed textual value, or {@code null} when absent, null, non-textual or blank. */
    private static String readText(JsonNode node) {
        if (node == null || node.isNull() || !node.isTextual()) {
            return null;
        }
        String value = node.asText().trim();
        if (value.isEmpty()) {
            return null;
        }
        return value.length() > MAX_TEXT_LENGTH ? value.substring(0, MAX_TEXT_LENGTH) : value;
    }

    /**
     * @return an absolute {@code http}/{@code https} URL, or {@code null}.
     *
     * <p>Anything with another scheme is dropped rather than stored. A {@code javascript:} or
     * {@code data:} value persisted into a user attribute would otherwise be rendered by any
     * theme or downstream application that displays the avatar.
     */
    private static String readHttpUrl(JsonNode node) {
        String value = readText(node);
        if (value == null) {
            return null;
        }
        try {
            URI uri = new URI(value);
            if (!uri.isAbsolute() || uri.getScheme() == null || uri.getHost() == null) {
                return null;
            }
            String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
            if (!"http".equals(scheme) && !"https".equals(scheme)) {
                return null;
            }
            return value;
        } catch (URISyntaxException e) {
            return null;
        }
    }
}
