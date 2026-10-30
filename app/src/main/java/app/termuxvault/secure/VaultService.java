package app.termuxvault.secure;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.UUID;

import javax.crypto.AEADBadTagException;

final class VaultService {
    static final int ARGON_MEMORY_KIB = 64 * 1024;
    static final int ARGON_ITERATIONS = 3;
    static final int ARGON_PARALLELISM = 4;
    static final int MAX_COMMAND_BYTES = 256 * 1024;
    static final byte[] AAD_VMK_PASSWORD = "termux-vault|vmk|passphrase|v1".getBytes(StandardCharsets.US_ASCII);
    static final byte[] AAD_VMK_BIOMETRIC = "termux-vault|vmk|biometric|v1".getBytes(StandardCharsets.US_ASCII);

    private VaultService() {}

    static Creation create(char[] passphrase) throws VaultException {
        PassphraseWarning.requireVaultPassphrase(passphrase);
        byte[] vmk = CryptoEngine.randomBytes(CryptoEngine.KEY_BYTES);
        byte[] salt = CryptoEngine.randomBytes(16);
        byte[] passKey = null;
        CryptoEngine.Blob wrap = null;
        try {
            passKey = CryptoEngine.deriveArgon2id(passphrase, salt, ARGON_MEMORY_KIB,
                    ARGON_ITERATIONS, ARGON_PARALLELISM);
            wrap = CryptoEngine.encrypt(passKey, vmk, AAD_VMK_PASSWORD);
            VaultState state = new VaultState();
            state.kdfSalt = CryptoEngine.toBase64(salt);
            state.kdfMemoryKiB = ARGON_MEMORY_KIB;
            state.kdfIterations = ARGON_ITERATIONS;
            state.kdfParallelism = ARGON_PARALLELISM;
            state.passVmkIv = CryptoEngine.toBase64(wrap.iv);
            state.passVmkCiphertext = CryptoEngine.toBase64(wrap.ciphertext);
            return new Creation(state, vmk);
        } catch (GeneralSecurityException exception) {
            CryptoEngine.wipe(vmk);
            throw new VaultException("Vault encryption failed", exception);
        } finally {
            CryptoEngine.wipe(salt);
            CryptoEngine.wipe(passKey);
            if (wrap != null) wrap.wipe();
        }
    }

    static byte[] unlockWithPassphrase(VaultState state, char[] passphrase) throws VaultException {
        byte[] salt = null;
        byte[] passKey = null;
        CryptoEngine.Blob wrap = null;
        try {
            salt = CryptoEngine.fromBase64(state.kdfSalt);
            passKey = CryptoEngine.deriveArgon2id(passphrase, salt, state.kdfMemoryKiB,
                    state.kdfIterations, state.kdfParallelism);
            wrap = CryptoEngine.Blob.fromStrings(state.passVmkIv, state.passVmkCiphertext);
            byte[] vmk = CryptoEngine.decrypt(passKey, wrap, AAD_VMK_PASSWORD);
            if (vmk.length != CryptoEngine.KEY_BYTES) {
                CryptoEngine.wipe(vmk);
                throw new VaultException("Vault key data is invalid");
            }
            return vmk;
        } catch (AEADBadTagException exception) {
            throw new VaultException(VaultException.Code.AUTHENTICATION_FAILED,
                    "Vault authentication failed");
        } catch (GeneralSecurityException exception) {
            throw new VaultException("Vault key could not be decrypted", exception);
        } catch (RuntimeException exception) {
            throw new VaultException("Vault key data is invalid", exception);
        } finally {
            CryptoEngine.wipe(salt);
            CryptoEngine.wipe(passKey);
            if (wrap != null) wrap.wipe();
        }
    }

    /**
     * Replaces the vault master key, re-wraps every entry DEK, and wraps the new master key with
     * {@code newPassphrase}. The previous master key cannot decrypt the updated vault. The biometric
     * wrapper is removed because it still holds the old master key; the caller must delete the
     * Keystore key after this mutation is persisted.
     *
     * @return {@code true} if a biometric wrapper was present and cleared
     */
    static boolean rotateMasterKey(VaultState state, byte[] oldVmk, char[] newPassphrase)
            throws VaultException {
        PassphraseWarning.requireVaultPassphrase(newPassphrase);
        if (oldVmk == null || oldVmk.length != CryptoEngine.KEY_BYTES) {
            throw new VaultException("Vault key is invalid");
        }
        byte[] newVmk = CryptoEngine.randomBytes(CryptoEngine.KEY_BYTES);
        try {
            for (VaultState.Entry entry : state.entries) {
                rewrapEntryDek(oldVmk, newVmk, entry);
            }
            wrapPassphrase(state, newVmk, newPassphrase);
            boolean biometricCleared = state.bioVmkIv != null || state.bioVmkCiphertext != null
                    || !state.bioPolicyAcknowledgements.isEmpty();
            state.bioVmkIv = null;
            state.bioVmkCiphertext = null;
            state.bioPolicyAcknowledgements.clear();
            return biometricCleared;
        } finally {
            CryptoEngine.wipe(newVmk);
        }
    }

    private static void wrapPassphrase(VaultState state, byte[] vmk, char[] newPassphrase)
            throws VaultException {
        byte[] salt = CryptoEngine.randomBytes(16);
        byte[] passKey = null;
        CryptoEngine.Blob wrap = null;
        try {
            passKey = CryptoEngine.deriveArgon2id(newPassphrase, salt, ARGON_MEMORY_KIB,
                    ARGON_ITERATIONS, ARGON_PARALLELISM);
            wrap = CryptoEngine.encrypt(passKey, vmk, AAD_VMK_PASSWORD);
            state.kdfSalt = CryptoEngine.toBase64(salt);
            state.kdfMemoryKiB = ARGON_MEMORY_KIB;
            state.kdfIterations = ARGON_ITERATIONS;
            state.kdfParallelism = ARGON_PARALLELISM;
            state.passVmkIv = CryptoEngine.toBase64(wrap.iv);
            state.passVmkCiphertext = CryptoEngine.toBase64(wrap.ciphertext);
        } catch (GeneralSecurityException exception) {
            throw new VaultException("Vault encryption failed", exception);
        } finally {
            CryptoEngine.wipe(salt);
            CryptoEngine.wipe(passKey);
            if (wrap != null) wrap.wipe();
        }
    }

    private static void rewrapEntryDek(byte[] oldVmk, byte[] newVmk, VaultState.Entry entry)
            throws VaultException {
        CryptoEngine.Blob oldWrap = null;
        CryptoEngine.Blob newWrap = null;
        byte[] dek = null;
        try {
            oldWrap = CryptoEngine.Blob.fromStrings(entry.dekIv, entry.dekCiphertext);
            dek = CryptoEngine.decrypt(oldVmk, oldWrap, aad(entry.id, "dek"));
            if (dek.length != CryptoEngine.KEY_BYTES) {
                throw new VaultException("Command data is invalid");
            }
            newWrap = CryptoEngine.encrypt(newVmk, dek, aad(entry.id, "dek"));
            entry.dekIv = CryptoEngine.toBase64(newWrap.iv);
            entry.dekCiphertext = CryptoEngine.toBase64(newWrap.ciphertext);
        } catch (VaultException exception) {
            throw exception;
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new VaultException("Command encryption failed", exception);
        } finally {
            if (oldWrap != null) oldWrap.wipe();
            if (newWrap != null) newWrap.wipe();
            CryptoEngine.wipe(dek);
        }
    }

    static VaultState.Entry encryptNewEntry(byte[] vmk, String title, String icon, char[] command,
                                            boolean pauseAfterRun, boolean notifyWhenFinished,
                                            boolean hideTerminalOutput)
            throws VaultException {
        VaultState.Entry entry = new VaultState.Entry();
        entry.id = UUID.randomUUID().toString();
        entry.title = title;
        entry.icon = icon;
        entry.pauseAfterRun = pauseAfterRun;
        entry.notifyWhenFinished = notifyWhenFinished;
        entry.hideTerminalOutput = hideTerminalOutput;
        entry.createdAt = System.currentTimeMillis();
        entry.modifiedAt = entry.createdAt;
        encryptEntryPayload(vmk, entry, command);
        return entry;
    }

    static void updateEntry(byte[] vmk, VaultState.Entry entry, String title, String icon,
                            char[] command, boolean pauseAfterRun, boolean notifyWhenFinished,
                            boolean hideTerminalOutput)
            throws VaultException {
        entry.title = title;
        entry.icon = icon;
        entry.pauseAfterRun = pauseAfterRun;
        entry.notifyWhenFinished = notifyWhenFinished;
        entry.hideTerminalOutput = hideTerminalOutput;
        entry.modifiedAt = System.currentTimeMillis();
        encryptEntryPayload(vmk, entry, command);
    }

    private static void encryptEntryPayload(byte[] vmk, VaultState.Entry entry, char[] command)
            throws VaultException {
        byte[] commandBytes = null;
        byte[] dek = CryptoEngine.randomBytes(CryptoEngine.KEY_BYTES);
        CryptoEngine.Blob dekWrap = null;
        CryptoEngine.Blob commandWrap = null;
        try {
            commandBytes = CryptoEngine.charsToUtf8(command);
            if (commandBytes.length == 0 || commandBytes.length > MAX_COMMAND_BYTES) {
                throw new VaultException("Command must be between 1 byte and 256 KiB");
            }
            for (byte value : commandBytes) {
                if (value == 0) throw new VaultException("Commands cannot contain NUL bytes");
            }
            dekWrap = CryptoEngine.encrypt(vmk, dek, aad(entry.id, "dek"));
            commandWrap = CryptoEngine.encrypt(dek, commandBytes, aad(entry.id, "command"));
            entry.dekIv = CryptoEngine.toBase64(dekWrap.iv);
            entry.dekCiphertext = CryptoEngine.toBase64(dekWrap.ciphertext);
            entry.commandIv = CryptoEngine.toBase64(commandWrap.iv);
            entry.commandCiphertext = CryptoEngine.toBase64(commandWrap.ciphertext);
        } catch (VaultException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new VaultException("Command encryption failed", exception);
        } finally {
            CryptoEngine.wipe(commandBytes);
            CryptoEngine.wipe(dek);
            if (dekWrap != null) dekWrap.wipe();
            if (commandWrap != null) commandWrap.wipe();
        }
    }

    static byte[] decryptEntry(byte[] vmk, VaultState.Entry entry) throws VaultException {
        CryptoEngine.Blob dekWrap = null;
        CryptoEngine.Blob commandWrap = null;
        byte[] dek = null;
        try {
            dekWrap = CryptoEngine.Blob.fromStrings(entry.dekIv, entry.dekCiphertext);
            dek = CryptoEngine.decrypt(vmk, dekWrap, aad(entry.id, "dek"));
            if (dek.length != CryptoEngine.KEY_BYTES) throw new VaultException("Command data is invalid");
            commandWrap = CryptoEngine.Blob.fromStrings(entry.commandIv, entry.commandCiphertext);
            byte[] command = CryptoEngine.decrypt(dek, commandWrap, aad(entry.id, "command"));
            if (command.length == 0 || command.length > MAX_COMMAND_BYTES) {
                CryptoEngine.wipe(command);
                throw new VaultException("Command data is invalid");
            }
            for (byte value : command) {
                if (value == 0) {
                    CryptoEngine.wipe(command);
                    throw new VaultException("Command data is invalid");
                }
            }
            return command;
        } catch (VaultException exception) {
            throw exception;
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new VaultException("Command could not be decrypted", exception);
        } finally {
            if (dekWrap != null) dekWrap.wipe();
            if (commandWrap != null) commandWrap.wipe();
            CryptoEngine.wipe(dek);
        }
    }

    private static byte[] aad(String id, String purpose) {
        return ("termux-vault|entry|" + id + "|" + purpose + "|v1")
                .getBytes(StandardCharsets.US_ASCII);
    }

    static final class Creation {
        final VaultState state;
        final byte[] vmk;

        Creation(VaultState state, byte[] vmk) {
            this.state = state;
            this.vmk = vmk;
        }

        void wipe() {
            CryptoEngine.wipe(vmk);
        }
    }
}
