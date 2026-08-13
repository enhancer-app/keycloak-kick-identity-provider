/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

/**
 * Raised when a Kick profile response cannot be turned into a trustworthy {@link KickProfile}.
 *
 * <p>Every message carried by this exception is a fixed, constant string taken from
 * {@link Reason}. Remote payloads, tokens and secrets are never interpolated into it, so the
 * message is always safe to log and to surface in a Keycloak error page.
 */
public class KickProfileException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Machine-readable classification of the failure. The associated message is a compile-time
     * constant, which is what makes it safe to propagate.
     */
    public enum Reason {
        /** The response body was not parseable JSON, or the root was not a JSON object. */
        MALFORMED_JSON("Kick profile response was not a valid JSON object"),
        /** The {@code data} property was absent or null. */
        MISSING_DATA("Kick profile response did not contain a 'data' property"),
        /** The {@code data} property was present but not a JSON array. */
        DATA_NOT_ARRAY("Kick profile response 'data' property was not an array"),
        /** The {@code data} array contained no elements. */
        EMPTY_DATA("Kick profile response contained an empty 'data' array"),
        /** The first {@code data} element was not a JSON object. */
        ENTRY_NOT_OBJECT("Kick profile response 'data' entry was not a JSON object"),
        /** {@code user_id} was absent or null. */
        MISSING_USER_ID("Kick profile response did not contain a 'user_id' value"),
        /** {@code user_id} was present but not a usable non-negative integer identifier. */
        INVALID_USER_ID("Kick profile response contained an unusable 'user_id' value");

        private final String message;

        Reason(String message) {
            this.message = message;
        }

        /** @return the fixed, payload-free message for this reason. */
        public String getMessage() {
            return message;
        }
    }

    private final Reason reason;

    public KickProfileException(Reason reason) {
        super(reason.getMessage());
        this.reason = reason;
    }

    // Note: there is deliberately no (Reason, Throwable) constructor. Jackson parse errors embed a
    // fragment of the offending payload in their message and stack trace, so chaining them would
    // leak remote response content into Keycloak's logs the moment anything logs the exception.

    public Reason getReason() {
        return reason;
    }
}
