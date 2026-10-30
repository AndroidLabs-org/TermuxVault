package app.termuxvault.secure;

import android.content.Context;
import android.system.ErrnoException;
import android.system.Os;
import android.util.AtomicFile;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

final class VaultStore {
    static final int MAX_ENTRIES = 200;
    static final int MAX_BIOMETRIC_POLICY_ACKNOWLEDGEMENTS = 64;
    static final int MAX_FILE_BYTES = 2 * 1024 * 1024;
    private static final Object IO_LOCK = new Object();
    private static long mutationEpoch;

    private final AtomicFile file;

    VaultStore(Context context) {
        File location = new File(context.getNoBackupFilesDir(), "vault-state.json");
        file = new AtomicFile(location);
    }

    boolean exists() {
        synchronized (IO_LOCK) {
            File base = file.getBaseFile();
            return base.isFile() || new File(base.getPath() + ".bak").isFile();
        }
    }

    VaultState load() throws VaultException {
        synchronized (IO_LOCK) {
            if (!exists()) throw new VaultException("Vault is not initialized");
            try (FileInputStream input = file.openRead()) {
                long fileLength = input.getChannel().size();
                if (fileLength <= 0 || fileLength > MAX_FILE_BYTES) {
                    throw new VaultException("Vault data is invalid");
                }
                int expectedLength = (int) fileLength;
                byte[] bytes = new byte[expectedLength];
                int offset = 0;
                while (offset < bytes.length) {
                    int count = input.read(bytes, offset, bytes.length - offset);
                    if (count < 0) break;
                    offset += count;
                }
                if (offset != bytes.length || input.read() != -1) {
                    CryptoEngine.wipe(bytes);
                    throw new VaultException("Vault data is invalid");
                }
                if (bytes.length == 0 || bytes.length > MAX_FILE_BYTES) {
                    CryptoEngine.wipe(bytes);
                    throw new VaultException("Vault data is invalid");
                }
                String json = new String(bytes, StandardCharsets.UTF_8);
                CryptoEngine.wipe(bytes);
                VaultState state = VaultState.fromJson(new JSONObject(json));
                validate(state);
                return state;
            } catch (VaultException exception) {
                throw exception;
            } catch (Exception exception) {
                throw new VaultException("Vault data could not be read", exception);
            }
        }
    }

    void save(VaultState state) throws VaultException {
        synchronized (IO_LOCK) {
            validate(state);
            FileOutputStream output = null;
            byte[] bytes = null;
            try {
                bytes = state.toJson().toString().getBytes(StandardCharsets.UTF_8);
                if (bytes.length <= 0 || bytes.length > MAX_FILE_BYTES) {
                    throw new VaultException("Vault data is too large");
                }
                output = file.startWrite();
                output.write(bytes);
                file.finishWrite(output);
                output = null;
                mutationEpoch++;
                try {
                    Os.chmod(file.getBaseFile().getAbsolutePath(), 0600);
                } catch (ErrnoException ignored) {
                    // App-private storage is already created mode 0600 by Android.
                }
            } catch (VaultException exception) {
                if (output != null) file.failWrite(output);
                throw exception;
            } catch (Exception exception) {
                if (output != null) file.failWrite(output);
                throw new VaultException("Vault data could not be saved", exception);
            } finally {
                CryptoEngine.wipe(bytes);
            }
        }
    }

    /** Creates the initial vault without overwriting a vault created by another live flow. */
    byte[] saveInitialAndFingerprint(VaultState state) throws VaultException {
        synchronized (IO_LOCK) {
            if (exists()) throw new VaultException("Vault is already initialized");
            save(state);
            return snapshotFingerprint(state);
        }
    }

    void mutate(Mutation mutation) throws VaultException {
        synchronized (IO_LOCK) {
            VaultState state = load();
            mutation.apply(state);
            save(state);
        }
    }

    /**
     * Applies a mutation only if the vault is exactly the state that was authenticated. The
     * process-local epoch also detects an intervening idempotent write, such as deleting an
     * already-empty entry list. Pending authenticated work cannot silently undo a later action.
     */
    void mutateIfUnchanged(byte[] expectedFingerprint, Mutation mutation) throws VaultException {
        synchronized (IO_LOCK) {
            byte[] currentFingerprint = null;
            try {
                VaultState state = load();
                currentFingerprint = snapshotFingerprint(state);
                requireAuthenticatedSnapshot(expectedFingerprint, currentFingerprint);
                mutation.apply(state);
                save(state);
            } finally {
                CryptoEngine.wipe(currentFingerprint);
            }
        }
    }

    /**
     * Reads only from the exact encrypted vault snapshot that was authenticated. Keeping the
     * comparison and read under {@link #IO_LOCK} prevents a command or other protected value from
     * being substituted between authorization and use.
     */
    <T> T readIfUnchanged(byte[] expectedFingerprint, Reader<T> reader) throws VaultException {
        synchronized (IO_LOCK) {
            byte[] currentFingerprint = null;
            try {
                VaultState state = load();
                currentFingerprint = snapshotFingerprint(state);
                requireAuthenticatedSnapshot(expectedFingerprint, currentFingerprint);
                return reader.apply(state);
            } finally {
                CryptoEngine.wipe(currentFingerprint);
            }
        }
    }

    <T> T readLocked(Reader<T> reader) throws VaultException {
        synchronized (IO_LOCK) {
            return reader.apply(load());
        }
    }

    /** Returns a non-secret, short-lived identity for the current encrypted vault snapshot. */
    static byte[] snapshotFingerprint(VaultState state) throws VaultException {
        synchronized (IO_LOCK) {
            byte[] serialized = null;
            try {
                serialized = state.toJson().toString().getBytes(StandardCharsets.UTF_8);
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(serialized);
                long epoch = mutationEpoch;
                for (int shift = 56; shift >= 0; shift -= 8) {
                    digest.update((byte) (epoch >>> shift));
                }
                return digest.digest();
            } catch (NoSuchAlgorithmException | RuntimeException | org.json.JSONException exception) {
                throw new VaultException("Vault data is invalid", exception);
            } finally {
                CryptoEngine.wipe(serialized);
            }
        }
    }

    private static void requireAuthenticatedSnapshot(byte[] expected, byte[] current)
            throws VaultException {
        if (expected == null || current == null || !MessageDigest.isEqual(expected, current)) {
            throw new VaultException(
                    VaultException.Code.STATE_CHANGED,
                    "The vault changed after authorization. Review the current state and try again.");
        }
    }

    /** Authenticates and atomically persists an empty entry list without changing vault access. */
    int clearEntriesAuthenticated(char[] passphrase) throws VaultException {
        synchronized (IO_LOCK) {
            byte[] vmk = null;
            try {
                VaultState state = load();
                vmk = VaultService.unlockWithPassphrase(state, passphrase);
                int removed = state.entries.size();
                state.entries.clear();
                save(state);
                return removed;
            } catch (VaultException exception) {
                throw exception;
            } catch (RuntimeException exception) {
                throw new VaultException("Vault entries could not be deleted", exception);
            } finally {
                CryptoEngine.wipe(vmk);
            }
        }
    }

    /**
     * Removes the complete vault only after authenticating the supplied passphrase while the
     * process-wide storage lock is held. Keeping authentication and deletion in one operation
     * prevents a different vault state from being substituted between those steps.
     *
     * <p>The caller owns and must wipe {@code passphrase}.</p>
     */
    void deleteAuthenticated(char[] passphrase) throws VaultException {
        synchronized (IO_LOCK) {
            byte[] vmk = null;
            try {
                VaultState state = load();
                vmk = VaultService.unlockWithPassphrase(state, passphrase);
                file.delete();
                if (vaultFileRemains()) {
                    throw new VaultException("Vault data could not be deleted");
                }
                mutationEpoch++;
            } catch (VaultException exception) {
                throw exception;
            } catch (RuntimeException exception) {
                throw new VaultException("Vault data could not be deleted", exception);
            } finally {
                CryptoEngine.wipe(vmk);
            }
        }
    }

    private boolean vaultFileRemains() {
        File base = file.getBaseFile();
        return base.exists()
                || new File(base.getPath() + ".bak").exists()
                || new File(base.getPath() + ".new").exists();
    }

    private static void validate(VaultState state) throws VaultException {
        try {
            if (state == null || state.version != VaultState.CURRENT_VERSION) fail();
            byte[] salt = CryptoEngine.fromBase64(state.kdfSalt);
            if (salt.length < 16 || salt.length > 64) fail();
            CryptoEngine.wipe(salt);
            if (state.kdfMemoryKiB < 32 * 1024 || state.kdfMemoryKiB > 256 * 1024) fail();
            if (state.kdfIterations < 1 || state.kdfIterations > 10) fail();
            if (state.kdfParallelism < 1 || state.kdfParallelism > 4) fail();
            validateBlob(state.passVmkIv, state.passVmkCiphertext, 48, 48);
            if ((state.bioVmkIv == null) != (state.bioVmkCiphertext == null)) fail();
            if (state.bioVmkIv != null) validateBlob(state.bioVmkIv, state.bioVmkCiphertext, 48, 48);
            if (state.bioVmkIv == null && !state.bioPolicyAcknowledgements.isEmpty()) fail();
            if (!BiometricKeyPolicy.areCanonicalAcceptanceTokens(
                    state.bioPolicyAcknowledgements,
                    MAX_BIOMETRIC_POLICY_ACKNOWLEDGEMENTS)) fail();
            if (state.entries.size() > MAX_ENTRIES) fail();
            java.util.HashSet<String> entryIds = new java.util.HashSet<>();
            for (VaultState.Entry entry : state.entries) {
                if (entry.id == null || entry.id.length() != 36) fail();
                java.util.UUID.fromString(entry.id);
                if (!entryIds.add(entry.id)) fail();
                if (TextPolicy.isBlank(entry.title) || entry.title.length() > 80) fail();
                if (!EntryIcons.isKnown(entry.icon)) fail();
                validateBlob(entry.dekIv, entry.dekCiphertext, 48, 48);
                validateBlob(entry.commandIv, entry.commandCiphertext, 16, VaultService.MAX_COMMAND_BYTES + 16);
            }
            for (String digest : state.trustedTermuxCertificates) {
                if (digest == null || !digest.matches("[0-9A-F]{64}")) fail();
            }
        } catch (VaultException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new VaultException("Vault data is invalid", exception);
        }
    }

    private static void validateBlob(String ivString, String ciphertextString, int minCiphertext, int maxCiphertext)
            throws VaultException {
        byte[] iv = null;
        byte[] ciphertext = null;
        try {
            iv = CryptoEngine.fromBase64(ivString);
            ciphertext = CryptoEngine.fromBase64(ciphertextString);
            if (iv.length != CryptoEngine.GCM_IV_BYTES) fail();
            if (ciphertext.length < minCiphertext || ciphertext.length > maxCiphertext) fail();
        } finally {
            CryptoEngine.wipe(iv);
            CryptoEngine.wipe(ciphertext);
        }
    }

    private static void fail() throws VaultException {
        throw new VaultException("Vault data is invalid");
    }

    interface Mutation {
        void apply(VaultState state) throws VaultException;
    }

    interface Reader<T> {
        T apply(VaultState state) throws VaultException;
    }
}

final class VaultException extends Exception {
    enum Code {
        GENERAL,
        AUTHENTICATION_FAILED,
        STATE_CHANGED
    }

    private final Code code;

    VaultException(String message) {
        this(Code.GENERAL, message, null);
    }

    VaultException(String message, Throwable cause) {
        this(Code.GENERAL, message, cause);
    }

    VaultException(Code code, String message) {
        this(code, message, null);
    }

    VaultException(Code code, String message, Throwable cause) {
        super(message, cause);
        this.code = code == null ? Code.GENERAL : code;
    }

    boolean isAuthenticationFailure() {
        return code == Code.AUTHENTICATION_FAILED;
    }

    boolean isStateChanged() {
        return code == Code.STATE_CHANGED;
    }
}
