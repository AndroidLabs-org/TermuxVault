package app.termuxvault.secure;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/** Android-free model of the protections requested for the biometric Keystore key. */
final class BiometricKeyPolicy {
    private static final String ACKNOWLEDGEMENT_SCHEMA =
            "termux-vault-biometric-policy-ack-v1";
    private static final int MAX_REPORTED_LENGTH = 120;
    private static final int MAX_ACTION_LENGTH = 180;

    enum Field {
        POLICY_INSPECTION(
                "policy_inspection", "Android Keystore policy details", "Available"),
        ALGORITHM("algorithm", "Key algorithm", "AES"),
        KEY_SIZE("key_size", "Key size", "256 bits"),
        HARDWARE_BACKING(
                "hardware_backing", "Hardware-backed key storage", "Secure hardware"),
        HARDWARE_AUTHORIZATION(
                "hardware_authorization", "Biometric authorization enforcement",
                "Enforced by secure hardware"),
        AUTHENTICATION_REQUIRED(
                "authentication_required", "Authentication requirement", "Required"),
        AUTHENTICATOR_TYPE(
                "authenticator_type", "Allowed key authenticator", "Class 3 biometric only"),
        AUTHENTICATION_DURATION(
                "authentication_duration", "Authentication frequency", "Every key use"),
        ENROLLMENT_INVALIDATION(
                "enrollment_invalidation", "New-enrollment invalidation", "Enabled"),
        PURPOSES("purposes", "Key purposes", "Encrypt and decrypt only"),
        BLOCK_MODE("block_mode", "Block mode", "GCM only"),
        ENCRYPTION_PADDING("encryption_padding", "Encryption padding", "No padding only");

        final String id;
        final String label;
        final String expected;

        Field(String id, String label, String expected) {
            this.id = id;
            this.label = label;
            this.expected = expected;
        }
    }

    static final class Deviation {
        final Field field;
        final String reported;

        Deviation(Field field, String reported) {
            this.field = field;
            this.reported = normalize(reported, MAX_REPORTED_LENGTH);
        }

        String acceptanceToken() {
            // Include the policy schema and both sides of the comparison. A later release that
            // strengthens an expected value must require a fresh review even when a device keeps
            // reporting the same value. The persisted token still contains no raw policy value.
            String finding = ACKNOWLEDGEMENT_SCHEMA + '\n' + field.id + '\n'
                    + field.expected + '\n' + reported;
            return field.id + ':' + sha256(finding);
        }
    }

    static final class PolicyReport {
        private static final PolicyReport EXACT = new PolicyReport(Collections.emptyList());

        private final List<Deviation> deviations;

        private PolicyReport(List<Deviation> source) {
            deviations = Collections.unmodifiableList(new ArrayList<>(source));
        }

        static PolicyReport exact() {
            return EXACT;
        }

        boolean hasDeviations() {
            return !deviations.isEmpty();
        }

        List<Deviation> deviations() {
            return deviations;
        }

        List<String> acceptanceTokens() {
            List<String> tokens = new ArrayList<>(deviations.size());
            for (Deviation deviation : deviations) tokens.add(deviation.acceptanceToken());
            Collections.sort(tokens);
            return Collections.unmodifiableList(tokens);
        }

        boolean isAcknowledgedBy(Collection<String> acceptedTokens) {
            if (!hasDeviations()) return true;
            if (acceptedTokens == null || acceptedTokens.isEmpty()) return false;
            Set<String> accepted = new HashSet<>(acceptedTokens);
            for (Deviation deviation : deviations) {
                if (!accepted.contains(deviation.acceptanceToken())) return false;
            }
            return true;
        }

        void mergeAcknowledgementsInto(List<String> acceptedTokens, int maximumCount) {
            if (acceptedTokens == null || maximumCount < 0) {
                throw new IllegalArgumentException("Invalid acknowledgement collection");
            }
            Set<String> current = new HashSet<>();
            for (Deviation deviation : deviations) {
                current.add(deviation.acceptanceToken());
            }
            if (current.size() > maximumCount) {
                throw new IllegalArgumentException("Too many current biometric findings");
            }
            TreeSet<String> merged = new TreeSet<>(acceptedTokens);
            merged.addAll(current);
            while (merged.size() > maximumCount) {
                String removable = null;
                for (String token : merged) {
                    if (!current.contains(token)) {
                        removable = token;
                        break;
                    }
                }
                if (removable == null) {
                    throw new IllegalArgumentException("Too many current biometric findings");
                }
                merged.remove(removable);
            }
            acceptedTokens.clear();
            acceptedTokens.addAll(merged);
        }

        String friendlyWarningMessage(String actionReason) {
            StringBuilder message = new StringBuilder(1024);
            message.append("Termux Vault could not confirm every requested biometric protection "
                    + "on this device. This can happen on older devices or customized firmware "
                    + "and does not necessarily mean your biometrics are unsafe.\n\n");
            String action = actionReason == null ? ""
                    : normalize(actionReason, MAX_ACTION_LENGTH);
            if (!action.isEmpty() && !"Unavailable".equals(action)) {
                message.append("Action:\n").append(action).append("\n\n");
            }
            message.append("Could not confirm:\n");
            for (Deviation deviation : deviations) {
                message.append("\u2022 ").append(deviation.field.label).append('\n');
            }
            message.append("\nYou can still use biometric unlock, but its protection may be "
                    + "weaker than Termux Vault normally expects. Your vault passphrase will "
                    + "remain available.");
            return message.toString();
        }

        String technicalDetails() {
            StringBuilder details = new StringBuilder(768);
            for (Deviation deviation : deviations) {
                details.append(deviation.field.label)
                        .append("\nExpected: ").append(deviation.field.expected)
                        .append("\nReported: ").append(deviation.reported).append("\n\n");
            }
            if (details.length() >= 2) details.setLength(details.length() - 2);
            return details.toString();
        }
    }

    static final class Builder {
        private final List<Deviation> deviations = new ArrayList<>();

        Builder check(Field field, boolean matches, String reported) {
            if (!matches) deviations.add(new Deviation(field, reported));
            return this;
        }

        Builder unavailable(Field field) {
            return check(field, false, "Unavailable");
        }

        PolicyReport build() {
            return deviations.isEmpty() ? PolicyReport.exact() : new PolicyReport(deviations);
        }
    }

    private BiometricKeyPolicy() {}

    /**
     * Android's public KeyInfo contract uses -1 for auth-per-use keys, while the Keystore2
     * provider returns 0 when the per-use key has no AUTH_TIMEOUT tag. The corresponding
     * KeyGenParameterSpec API also defines a requested timeout of 0 as authentication for every
     * use. No positive duration is an exact match.
     */
    static boolean isPerUseAuthenticationDuration(int seconds) {
        return seconds == -1 || seconds == 0;
    }

    static String normalize(String value, int maximumLength) {
        if (value == null) return "Unavailable";
        if (maximumLength <= 0) return "Unavailable";
        StringBuilder result = new StringBuilder(Math.min(value.length(), maximumLength));
        boolean pendingSpace = false;
        for (int offset = 0; offset < value.length() && result.length() < maximumLength;) {
            int codePoint = value.codePointAt(offset);
            offset += Character.charCount(codePoint);
            int type = Character.getType(codePoint);
            if (type == Character.CONTROL || type == Character.FORMAT
                    || type == Character.LINE_SEPARATOR || type == Character.PARAGRAPH_SEPARATOR
                    || Character.isWhitespace(codePoint)) {
                pendingSpace = result.length() > 0;
                continue;
            }
            if (pendingSpace && result.length() < maximumLength) result.append(' ');
            pendingSpace = false;
            int width = Character.charCount(codePoint);
            if (result.length() + width > maximumLength) break;
            result.appendCodePoint(codePoint);
        }
        String normalized = result.toString().trim();
        return normalized.isEmpty() ? "Unavailable" : normalized;
    }

    static boolean isValidAcceptanceToken(String token) {
        if (token == null || token.length() < 67 || token.length() > 105) return false;
        int separator = token.indexOf(':');
        if (separator <= 0 || separator != token.length() - 65) return false;
        String field = token.substring(0, separator);
        if (!field.matches("[a-z_]{2,40}")) return false;
        boolean knownField = false;
        for (Field known : Field.values()) {
            if (known.id.equals(field)) {
                knownField = true;
                break;
            }
        }
        if (!knownField) return false;
        return token.substring(separator + 1).matches("[0-9a-f]{64}");
    }

    static boolean areCanonicalAcceptanceTokens(List<String> tokens, int maximumCount) {
        if (tokens == null || maximumCount < 0 || tokens.size() > maximumCount) return false;
        String previous = null;
        for (String token : tokens) {
            if (!isValidAcceptanceToken(token)
                    || (previous != null && previous.compareTo(token) >= 0)) return false;
            previous = token;
        }
        return true;
    }

    private static String sha256(String value) {
        byte[] input = value.getBytes(StandardCharsets.UTF_8);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(input);
            try {
                char[] digits = "0123456789abcdef".toCharArray();
                char[] encoded = new char[hashed.length * 2];
                for (int index = 0; index < hashed.length; index++) {
                    int current = hashed[index] & 0xff;
                    encoded[index * 2] = digits[current >>> 4];
                    encoded[index * 2 + 1] = digits[current & 0x0f];
                }
                return new String(encoded);
            } finally {
                CryptoEngine.wipe(hashed);
            }
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        } finally {
            CryptoEngine.wipe(input);
        }
    }
}
