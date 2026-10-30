package app.termuxvault.secure;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

final class CompletionAuth {
    static final int RUN_ID_BYTES = 16;
    static final int TOKEN_BYTES = 32;

    private CompletionAuth() {}

    static String hex(byte[] bytes) {
        char[] result = new char[bytes.length * 2];
        char[] alphabet = "0123456789abcdef".toCharArray();
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            result[i * 2] = alphabet[value >>> 4];
            result[i * 2 + 1] = alphabet[value & 0x0f];
        }
        return new String(result);
    }

    static boolean isLowerHex(String value, int bytes) {
        if (value == null || value.length() != bytes * 2) return false;
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            if (!((character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f'))) return false;
        }
        return true;
    }

    static byte[] decodeHex(String value, int bytes) {
        if (!isLowerHex(value, bytes)) return null;
        byte[] decoded = new byte[bytes];
        for (int i = 0; i < bytes; i++) {
            int high = Character.digit(value.charAt(i * 2), 16);
            int low = Character.digit(value.charAt(i * 2 + 1), 16);
            decoded[i] = (byte) ((high << 4) | low);
        }
        return decoded;
    }

    static byte[] hash(byte[] token) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(token);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    static boolean matches(String expectedHashBase64, String tokenHex) {
        byte[] token = null;
        byte[] actual = null;
        byte[] expected = null;
        try {
            token = decodeHex(tokenHex, TOKEN_BYTES);
            if (token == null) return false;
            actual = hash(token);
            expected = CryptoEngine.fromBase64(expectedHashBase64);
            return expected.length == 32 && CryptoEngine.equalsConstantTime(expected, actual);
        } catch (IllegalArgumentException exception) {
            return false;
        } finally {
            CryptoEngine.wipe(token);
            CryptoEngine.wipe(actual);
            CryptoEngine.wipe(expected);
        }
    }
}
