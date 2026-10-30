package app.termuxvault.secure;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class CryptoEngine {
    static final int KEY_BYTES = 32;
    static final int GCM_IV_BYTES = 12;
    static final int GCM_TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoEngine() {}

    static byte[] randomBytes(int length) {
        byte[] result = new byte[length];
        RANDOM.nextBytes(result);
        return result;
    }

    static Blob encrypt(byte[] key, byte[] plaintext, byte[] aad) throws GeneralSecurityException {
        byte[] iv = randomBytes(GCM_IV_BYTES);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(aad);
        return new Blob(iv, cipher.doFinal(plaintext));
    }

    static byte[] decrypt(byte[] key, Blob blob, byte[] aad) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, blob.iv));
        cipher.updateAAD(aad);
        return cipher.doFinal(blob.ciphertext);
    }

    static byte[] deriveArgon2id(char[] passphrase, byte[] salt, int memoryKiB, int iterations,
                                 int parallelism) {
        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withMemoryAsKB(memoryKiB)
                .withIterations(iterations)
                .withParallelism(parallelism)
                .build();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(parameters);
        byte[] key = new byte[KEY_BYTES];
        generator.generateBytes(passphrase, key);
        return key;
    }

    static byte[] charsToUtf8(char[] chars) throws CharacterCodingException {
        var encoder = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        int capacity = Math.max(1, (int) Math.ceil(chars.length * encoder.maxBytesPerChar()));
        ByteBuffer buffer = ByteBuffer.allocate(capacity);
        try {
            encoder.encode(CharBuffer.wrap(chars), buffer, true);
            encoder.flush(buffer);
            buffer.flip();
            byte[] result = new byte[buffer.remaining()];
            buffer.get(result);
            return result;
        } finally {
            wipe(buffer.array());
        }
    }

    static char[] utf8ToChars(byte[] bytes) throws CharacterCodingException {
        var decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        CharBuffer buffer = CharBuffer.allocate(Math.max(1, bytes.length));
        try {
            decoder.decode(ByteBuffer.wrap(bytes), buffer, true);
            decoder.flush(buffer);
            buffer.flip();
            char[] result = new char[buffer.remaining()];
            buffer.get(result);
            return result;
        } finally {
            wipe(buffer.array());
        }
    }

    static String toBase64(byte[] bytes) {
        return Base64.getEncoder().withoutPadding().encodeToString(bytes);
    }

    static byte[] fromBase64(String value) {
        if (value == null || value.length() > VaultStore.MAX_FILE_BYTES) {
            throw new IllegalArgumentException("Invalid encoded data");
        }
        return Base64.getDecoder().decode(value);
    }

    static boolean equalsConstantTime(byte[] first, byte[] second) {
        return first != null && second != null && MessageDigest.isEqual(first, second);
    }

    static void wipe(byte[] bytes) {
        if (bytes != null) Arrays.fill(bytes, (byte) 0);
    }

    static void wipe(char[] chars) {
        if (chars != null) Arrays.fill(chars, '\0');
    }

    static final class Blob {
        final byte[] iv;
        final byte[] ciphertext;

        Blob(byte[] iv, byte[] ciphertext) {
            this.iv = iv;
            this.ciphertext = ciphertext;
        }

        static Blob fromStrings(String iv, String ciphertext) {
            return new Blob(fromBase64(iv), fromBase64(ciphertext));
        }

        void wipe() {
            CryptoEngine.wipe(iv);
            CryptoEngine.wipe(ciphertext);
        }
    }
}
