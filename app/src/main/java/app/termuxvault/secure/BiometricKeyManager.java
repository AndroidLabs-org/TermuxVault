package app.termuxvault.secure;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

final class BiometricKeyManager {
    static final String KEY_ALIAS = "termux-vault-biometric-v1";

    enum KeyStatus {
        USABLE,
        MISSING,
        INVALIDATED,
        UNUSABLE
    }

    static final class ManagedKey {
        final SecretKey key;
        final BiometricKeyPolicy.PolicyReport policyReport;

        ManagedKey(SecretKey key, BiometricKeyPolicy.PolicyReport policyReport) {
            this.key = key;
            this.policyReport = policyReport;
        }
    }

    static final class KeyInspection {
        final KeyStatus status;
        final BiometricKeyPolicy.PolicyReport policyReport;

        KeyInspection(KeyStatus status, BiometricKeyPolicy.PolicyReport policyReport) {
            this.status = status;
            this.policyReport = policyReport;
        }
    }

    private BiometricKeyManager() {}

    static ManagedKey createFreshKey() throws GeneralSecurityException {
        deleteKey();
        KeyGenerator generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
                .build();
        generator.init(spec);
        SecretKey key = generator.generateKey();
        return new ManagedKey(key, inspectPolicy(key));
    }

    static ManagedKey loadKey() throws GeneralSecurityException {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        try {
            store.load(null);
        } catch (IOException exception) {
            throw new GeneralSecurityException("Android Keystore could not be loaded", exception);
        }
        java.security.Key key = store.getKey(KEY_ALIAS, null);
        if (!(key instanceof SecretKey secretKey)) {
            throw new GeneralSecurityException("Biometric key is missing");
        }
        return new ManagedKey(secretKey, inspectPolicy(secretKey));
    }

    static boolean hasKey() {
        try {
            KeyStore store = KeyStore.getInstance("AndroidKeyStore");
            store.load(null);
            return store.containsAlias(KEY_ALIAS);
        } catch (Exception exception) {
            return false;
        }
    }

    static KeyInspection inspectDecryptionKey(byte[] iv) {
        if (iv == null || iv.length != CryptoEngine.GCM_IV_BYTES) {
            return new KeyInspection(KeyStatus.UNUSABLE,
                    BiometricKeyPolicy.PolicyReport.exact());
        }
        if (!hasKey()) {
            return new KeyInspection(KeyStatus.MISSING,
                    BiometricKeyPolicy.PolicyReport.exact());
        }
        try {
            ManagedKey managedKey = loadKey();
            newDecryptCipher(managedKey.key, iv);
            return new KeyInspection(KeyStatus.USABLE, managedKey.policyReport);
        } catch (KeyPermanentlyInvalidatedException exception) {
            return new KeyInspection(KeyStatus.INVALIDATED,
                    BiometricKeyPolicy.PolicyReport.exact());
        } catch (GeneralSecurityException | RuntimeException exception) {
            return new KeyInspection(isPermanentlyInvalidated(exception)
                    ? KeyStatus.INVALIDATED : KeyStatus.UNUSABLE,
                    BiometricKeyPolicy.PolicyReport.exact());
        }
    }

    static boolean isPermanentlyInvalidated(Throwable failure) {
        Throwable cause = failure;
        while (cause != null) {
            if (cause instanceof KeyPermanentlyInvalidatedException) return true;
            cause = cause.getCause();
        }
        return false;
    }

    static void deleteKey() throws GeneralSecurityException {
        try {
            KeyStore store = KeyStore.getInstance("AndroidKeyStore");
            store.load(null);
            if (store.containsAlias(KEY_ALIAS)) store.deleteEntry(KEY_ALIAS);
        } catch (IOException exception) {
            throw new GeneralSecurityException("Android Keystore could not be loaded", exception);
        } catch (RuntimeException exception) {
            throw new GeneralSecurityException(
                    "Android Keystore key could not be deleted", exception);
        }
    }

    static Cipher newEncryptCipher(SecretKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher;
    }

    static Cipher newDecryptCipher(SecretKey key, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key,
                new GCMParameterSpec(CryptoEngine.GCM_TAG_BITS, iv));
        return cipher;
    }

    /** Must only be called with the CryptoObject returned by a successful biometric prompt. */
    static byte[] finishAuthenticatedEncryption(Cipher cipher, byte[] plaintext)
            throws GeneralSecurityException {
        cipher.updateAAD(VaultService.AAD_VMK_BIOMETRIC);
        return cipher.doFinal(plaintext);
    }

    /** Must only be called with the CryptoObject returned by a successful biometric prompt. */
    static byte[] finishAuthenticatedDecryption(Cipher cipher, byte[] ciphertext)
            throws GeneralSecurityException {
        cipher.updateAAD(VaultService.AAD_VMK_BIOMETRIC);
        return cipher.doFinal(ciphertext);
    }

    @SuppressWarnings("deprecation")
    private static BiometricKeyPolicy.PolicyReport inspectPolicy(SecretKey key) {
        BiometricKeyPolicy.Builder report = new BiometricKeyPolicy.Builder();
        String algorithm;
        try {
            algorithm = BiometricKeyPolicy.normalize(key.getAlgorithm(), 40);
        } catch (RuntimeException ignored) {
            algorithm = "Unavailable";
        }
        report.check(BiometricKeyPolicy.Field.ALGORITHM,
                KeyProperties.KEY_ALGORITHM_AES.equals(algorithm), algorithm);

        final KeyInfo info;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(
                    key.getAlgorithm(), "AndroidKeyStore");
            info = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
        } catch (GeneralSecurityException | RuntimeException ignored) {
            return report.unavailable(BiometricKeyPolicy.Field.POLICY_INSPECTION)
                    .unavailable(BiometricKeyPolicy.Field.KEY_SIZE)
                    .unavailable(BiometricKeyPolicy.Field.HARDWARE_BACKING)
                    .unavailable(BiometricKeyPolicy.Field.HARDWARE_AUTHORIZATION)
                    .unavailable(BiometricKeyPolicy.Field.AUTHENTICATION_REQUIRED)
                    .unavailable(BiometricKeyPolicy.Field.AUTHENTICATOR_TYPE)
                    .unavailable(BiometricKeyPolicy.Field.AUTHENTICATION_DURATION)
                    .unavailable(BiometricKeyPolicy.Field.ENROLLMENT_INVALIDATION)
                    .unavailable(BiometricKeyPolicy.Field.PURPOSES)
                    .unavailable(BiometricKeyPolicy.Field.BLOCK_MODE)
                    .unavailable(BiometricKeyPolicy.Field.ENCRYPTION_PADDING)
                    .build();
        }

        try {
            int keySize = info.getKeySize();
            report.check(BiometricKeyPolicy.Field.KEY_SIZE,
                    keySize == CryptoEngine.KEY_BYTES * 8, keySize + " bits");
        } catch (RuntimeException ignored) {
            report.unavailable(BiometricKeyPolicy.Field.KEY_SIZE);
        }

        try {
            if (Build.VERSION.SDK_INT >= 31) {
                int level = info.getSecurityLevel();
                boolean secure = level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                        || level == KeyProperties.SECURITY_LEVEL_STRONGBOX
                        || level == KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE;
                report.check(BiometricKeyPolicy.Field.HARDWARE_BACKING,
                        secure, securityLevelName(level));
            } else {
                boolean secure = info.isInsideSecureHardware();
                report.check(BiometricKeyPolicy.Field.HARDWARE_BACKING,
                        secure, secure ? "Secure hardware" : "Software or unknown");
            }
        } catch (RuntimeException ignored) {
            report.unavailable(BiometricKeyPolicy.Field.HARDWARE_BACKING);
        }

        try {
            boolean enforced = info.isUserAuthenticationRequirementEnforcedBySecureHardware();
            report.check(BiometricKeyPolicy.Field.HARDWARE_AUTHORIZATION, enforced,
                    enforced ? "Enforced by secure hardware" : "Not hardware-enforced");
        } catch (RuntimeException ignored) {
            report.unavailable(BiometricKeyPolicy.Field.HARDWARE_AUTHORIZATION);
        }

        try {
            boolean required = info.isUserAuthenticationRequired();
            report.check(BiometricKeyPolicy.Field.AUTHENTICATION_REQUIRED, required,
                    required ? "Required" : "Not required by the key");
        } catch (RuntimeException ignored) {
            report.unavailable(BiometricKeyPolicy.Field.AUTHENTICATION_REQUIRED);
        }

        try {
            int type = info.getUserAuthenticationType();
            report.check(BiometricKeyPolicy.Field.AUTHENTICATOR_TYPE,
                    type == KeyProperties.AUTH_BIOMETRIC_STRONG, authenticatorTypeName(type));
        } catch (RuntimeException ignored) {
            report.unavailable(BiometricKeyPolicy.Field.AUTHENTICATOR_TYPE);
        }

        try {
            int duration = info.getUserAuthenticationValidityDurationSeconds();
            report.check(BiometricKeyPolicy.Field.AUTHENTICATION_DURATION,
                    BiometricKeyPolicy.isPerUseAuthenticationDuration(duration),
                    duration == -1 || duration == 0
                            ? "Every key use (" + duration + ')'
                            : duration + " seconds");
        } catch (RuntimeException ignored) {
            report.unavailable(BiometricKeyPolicy.Field.AUTHENTICATION_DURATION);
        }

        try {
            boolean invalidates = info.isInvalidatedByBiometricEnrollment();
            report.check(BiometricKeyPolicy.Field.ENROLLMENT_INVALIDATION, invalidates,
                    invalidates ? "Enabled" : "Not enabled");
        } catch (RuntimeException ignored) {
            report.unavailable(BiometricKeyPolicy.Field.ENROLLMENT_INVALIDATION);
        }

        try {
            int purposes = info.getPurposes();
            int expected = KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT;
            report.check(BiometricKeyPolicy.Field.PURPOSES,
                    purposes == expected, purposesName(purposes));
        } catch (RuntimeException ignored) {
            report.unavailable(BiometricKeyPolicy.Field.PURPOSES);
        }

        try {
            String[] modes = info.getBlockModes();
            report.check(BiometricKeyPolicy.Field.BLOCK_MODE,
                    containsOnly(modes, KeyProperties.BLOCK_MODE_GCM), arrayName(modes));
        } catch (RuntimeException ignored) {
            report.unavailable(BiometricKeyPolicy.Field.BLOCK_MODE);
        }

        try {
            String[] paddings = info.getEncryptionPaddings();
            report.check(BiometricKeyPolicy.Field.ENCRYPTION_PADDING,
                    containsOnly(paddings, KeyProperties.ENCRYPTION_PADDING_NONE),
                    arrayName(paddings));
        } catch (RuntimeException ignored) {
            report.unavailable(BiometricKeyPolicy.Field.ENCRYPTION_PADDING);
        }
        return report.build();
    }

    private static String securityLevelName(int level) {
        if (level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT) {
            return "Trusted Execution Environment";
        }
        if (level == KeyProperties.SECURITY_LEVEL_STRONGBOX) return "StrongBox";
        if (level == KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE) {
            return "Secure hardware (vendor did not identify the level)";
        }
        if (level == KeyProperties.SECURITY_LEVEL_SOFTWARE) return "Software";
        return "Unknown level (" + level + ')';
    }

    private static String authenticatorTypeName(int value) {
        if (value == KeyProperties.AUTH_BIOMETRIC_STRONG) return "Class 3 biometric only";
        if (value == KeyProperties.AUTH_DEVICE_CREDENTIAL) return "Device credential only";
        if (value == (KeyProperties.AUTH_BIOMETRIC_STRONG
                | KeyProperties.AUTH_DEVICE_CREDENTIAL)) {
            return "Class 3 biometric or device credential";
        }
        return "Unexpected authenticator mask (" + value + ')';
    }

    private static String purposesName(int value) {
        int expected = KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT;
        if (value == expected) return "Encrypt and decrypt only";
        return "Purpose mask " + value;
    }

    private static String arrayName(String[] values) {
        if (values == null) return "Unavailable";
        String[] copy = Arrays.copyOf(values, Math.min(values.length, 8));
        for (int index = 0; index < copy.length; index++) {
            copy[index] = BiometricKeyPolicy.normalize(copy[index], 40);
        }
        Arrays.sort(copy);
        String result = Arrays.toString(copy);
        if (values.length > copy.length) result += " and " + (values.length - copy.length) + " more";
        return BiometricKeyPolicy.normalize(result, 120);
    }

    private static boolean containsOnly(String[] values, String expected) {
        return values != null && values.length == 1 && expected.equals(values[0]);
    }
}
