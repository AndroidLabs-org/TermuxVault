package app.termuxvault.secure;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.AEADBadTagException;

/** Versioned, clipboard-oriented portable backup formats. No backup data is written to disk here. */
final class BackupCodec {
    static final String ENCRYPTED_PREFIX = "TERMUXVAULT-ENCRYPTED-BACKUP-V1:";
    static final String PLAINTEXT_FORMAT = "termux-vault-plaintext-backup";

    private static final int FORMAT_VERSION = 1;
    private static final int SALT_BYTES = 16;
    private static final int MAX_PAYLOAD_BYTES = 4 * 1024 * 1024;
    private static final int MAX_BACKUP_TEXT_CHARS = 16 * 1024 * 1024;
    private static final int MAX_TITLE_UTF8_BYTES = 4 * 80;
    private static final int MAX_ICON_UTF8_BYTES = 64;
    private static final byte[] PAYLOAD_MAGIC = {'T', 'V', 'B', '1'};
    private static final byte[] ENVELOPE_MAGIC = {'T', 'V', 'E', '1'};
    private static final byte[] BACKUP_AAD =
            "termux-vault|portable-backup|v1".getBytes(StandardCharsets.US_ASCII);

    private BackupCodec() {}

    static char[] exportEncrypted(VaultState state, byte[] vmk, char[] backupPassphrase)
            throws VaultException {
        requireBackupPassphrase(backupPassphrase);
        Bundle bundle = null;
        byte[] payload = null;
        byte[] salt = null;
        byte[] key = null;
        CryptoEngine.Blob encrypted = null;
        ByteWriter envelope = null;
        byte[] envelopeBytes = null;
        byte[] encoded = null;
        try {
            bundle = bundleFromVault(state, vmk);
            payload = encodePayload(bundle);
            salt = CryptoEngine.randomBytes(SALT_BYTES);
            key = CryptoEngine.deriveArgon2id(backupPassphrase, salt,
                    VaultService.ARGON_MEMORY_KIB, VaultService.ARGON_ITERATIONS,
                    VaultService.ARGON_PARALLELISM);
            encrypted = CryptoEngine.encrypt(key, payload, BACKUP_AAD);

            envelope = new ByteWriter(MAX_PAYLOAD_BYTES + 128);
            envelope.putBytes(ENVELOPE_MAGIC);
            envelope.putInt(FORMAT_VERSION);
            envelope.putInt(VaultService.ARGON_MEMORY_KIB);
            envelope.putInt(VaultService.ARGON_ITERATIONS);
            envelope.putInt(VaultService.ARGON_PARALLELISM);
            envelope.putBytes(salt);
            envelope.putBytes(encrypted.iv);
            envelope.putInt(encrypted.ciphertext.length);
            envelope.putBytes(encrypted.ciphertext);
            envelopeBytes = envelope.copy();
            encoded = Base64.getEncoder().withoutPadding().encode(envelopeBytes);
            return prefixedAscii(ENCRYPTED_PREFIX, encoded);
        } catch (VaultException exception) {
            throw exception;
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new VaultException("Encrypted backup could not be created", exception);
        } finally {
            if (bundle != null) bundle.wipe();
            CryptoEngine.wipe(payload);
            CryptoEngine.wipe(salt);
            CryptoEngine.wipe(key);
            if (encrypted != null) encrypted.wipe();
            if (envelope != null) envelope.wipe();
            CryptoEngine.wipe(envelopeBytes);
            CryptoEngine.wipe(encoded);
        }
    }

    static char[] exportPlaintext(VaultState state, byte[] vmk) throws VaultException {
        Bundle bundle = null;
        byte[] validatedPayload = null;
        CharWriter output = null;
        try {
            bundle = bundleFromVault(state, vmk);
            // Enforce the same aggregate size and entry validation as the encrypted payload.
            validatedPayload = encodePayload(bundle);
            output = new CharWriter(MAX_BACKUP_TEXT_CHARS);
            writePlaintextJson(output, bundle);
            return output.copy();
        } finally {
            if (bundle != null) bundle.wipe();
            CryptoEngine.wipe(validatedPayload);
            if (output != null) output.wipe();
        }
    }

    static boolean isEncrypted(char[] text) {
        if (text == null || text.length == 0) return false;
        int start = skipWhitespace(text, 0, text.length);
        return regionMatches(text, start, ENCRYPTED_PREFIX);
    }

    static boolean isEncrypted(CharSequence text) {
        if (text == null || text.length() == 0) return false;
        int start = 0;
        while (start < text.length() && isJsonWhitespace(text.charAt(start))) start++;
        if (text.length() - start < ENCRYPTED_PREFIX.length()) return false;
        for (int index = 0; index < ENCRYPTED_PREFIX.length(); index++) {
            if (text.charAt(start + index) != ENCRYPTED_PREFIX.charAt(index)) return false;
        }
        return true;
    }

    static Bundle decode(char[] text, char[] backupPassphraseOrNull) throws VaultException {
        if (text == null || text.length == 0 || text.length > MAX_BACKUP_TEXT_CHARS) {
            throw invalidBackup();
        }
        if (isEncrypted(text)) {
            requireBackupPassphrase(backupPassphraseOrNull);
            return decodeEncrypted(text, backupPassphraseOrNull);
        }
        int start = skipWhitespace(text, 0, text.length);
        if (start >= text.length || text[start] != '{') throw invalidBackup();
        return decodePlaintext(text);
    }

    /** Atomically appends all decoded entries with fresh IDs. Existing entries are never modified. */
    static void appendToVault(VaultStore store, byte[] vmk, byte[] authenticatedFingerprint,
                              Bundle bundle) throws VaultException {
        if (store == null) throw new VaultException("Vault is unavailable");
        store.mutateIfUnchanged(authenticatedFingerprint,
                state -> appendToState(state, vmk, bundle));
    }

    /** Package-visible for deterministic unit coverage of merge semantics. */
    static void appendToState(VaultState state, byte[] vmk, Bundle bundle) throws VaultException {
        requireVmk(vmk);
        if (state == null || bundle == null || bundle.wiped) throw invalidBackup();
        long finalCount = (long) state.entries.size() + bundle.entries.size();
        if (finalCount > VaultStore.MAX_ENTRIES) {
            throw new VaultException("The backup does not fit in this vault");
        }
        for (PortableEntry source : bundle.entries) {
            validatePortableEntry(source);
            state.entries.add(VaultService.encryptNewEntry(vmk, source.title, source.icon,
                    source.command, source.pauseAfterRun, source.notifyWhenFinished,
                    source.hideTerminalOutput));
        }
    }

    private static Bundle bundleFromVault(VaultState state, byte[] vmk) throws VaultException {
        requireVmk(vmk);
        if (state == null || state.entries.size() > VaultStore.MAX_ENTRIES) {
            throw new VaultException("Vault data is invalid");
        }
        Bundle bundle = new Bundle();
        try {
            for (VaultState.Entry source : state.entries) {
                validateMetadata(source.title, source.icon);
                byte[] commandBytes = null;
                char[] command = null;
                try {
                    commandBytes = VaultService.decryptEntry(vmk, source);
                    command = CryptoEngine.utf8ToChars(commandBytes);
                    PortableEntry entry = new PortableEntry(source.title, source.icon, command,
                            source.pauseAfterRun, source.notifyWhenFinished,
                            source.hideTerminalOutput);
                    validatePortableEntry(entry);
                    bundle.entries.add(entry);
                    command = null;
                } catch (CharacterCodingException exception) {
                    throw new VaultException("Command data is invalid", exception);
                } finally {
                    CryptoEngine.wipe(commandBytes);
                    CryptoEngine.wipe(command);
                }
            }
            return bundle;
        } catch (VaultException | RuntimeException exception) {
            bundle.wipe();
            if (exception instanceof VaultException vaultException) throw vaultException;
            throw new VaultException("Backup could not be created", exception);
        }
    }

    private static byte[] encodePayload(Bundle bundle) throws VaultException {
        if (bundle == null || bundle.wiped || bundle.entries.size() > VaultStore.MAX_ENTRIES) {
            throw invalidBackup();
        }
        ByteWriter writer = new ByteWriter(MAX_PAYLOAD_BYTES);
        try {
            writer.putBytes(PAYLOAD_MAGIC);
            writer.putInt(FORMAT_VERSION);
            writer.putInt(bundle.entries.size());
            for (PortableEntry entry : bundle.entries) {
                validatePortableEntry(entry);
                byte[] title = null;
                byte[] icon = null;
                byte[] command = null;
                try {
                    title = strictUtf8(entry.title);
                    icon = strictUtf8(entry.icon);
                    command = CryptoEngine.charsToUtf8(entry.command);
                    if (title.length == 0 || title.length > MAX_TITLE_UTF8_BYTES
                            || icon.length == 0 || icon.length > MAX_ICON_UTF8_BYTES
                            || command.length == 0 || command.length > VaultService.MAX_COMMAND_BYTES
                            || containsNul(command)) {
                        throw invalidBackup();
                    }
                    writer.putInt(title.length);
                    writer.putBytes(title);
                    writer.putInt(icon.length);
                    writer.putBytes(icon);
                    writer.putInt(command.length);
                    writer.putBytes(command);
                    int flags = (entry.pauseAfterRun ? 1 : 0)
                            | (entry.notifyWhenFinished ? 2 : 0)
                            | (entry.hideTerminalOutput ? 4 : 0);
                    writer.putByte(flags);
                } catch (CharacterCodingException exception) {
                    throw new VaultException("Backup data is invalid", exception);
                } finally {
                    CryptoEngine.wipe(title);
                    CryptoEngine.wipe(icon);
                    CryptoEngine.wipe(command);
                }
            }
            return writer.copy();
        } finally {
            writer.wipe();
        }
    }

    private static Bundle decodePayload(byte[] payload) throws VaultException {
        if (payload == null || payload.length <= 0 || payload.length > MAX_PAYLOAD_BYTES) {
            throw invalidBackup();
        }
        ByteReader reader = new ByteReader(payload);
        Bundle bundle = new Bundle();
        try {
            reader.expect(PAYLOAD_MAGIC);
            if (reader.readInt() != FORMAT_VERSION) throw invalidBackup();
            int count = reader.readInt();
            if (count < 0 || count > VaultStore.MAX_ENTRIES) throw invalidBackup();
            for (int index = 0; index < count; index++) {
                byte[] titleBytes = null;
                byte[] iconBytes = null;
                byte[] commandBytes = null;
                char[] titleChars = null;
                char[] iconChars = null;
                char[] command = null;
                try {
                    titleBytes = reader.readLengthPrefixed(MAX_TITLE_UTF8_BYTES);
                    iconBytes = reader.readLengthPrefixed(MAX_ICON_UTF8_BYTES);
                    commandBytes = reader.readLengthPrefixed(VaultService.MAX_COMMAND_BYTES);
                    if (titleBytes.length == 0 || iconBytes.length == 0 || commandBytes.length == 0
                            || containsNul(commandBytes)) throw invalidBackup();
                    int flags = reader.readUnsignedByte();
                    if ((flags & ~7) != 0) throw invalidBackup();
                    titleChars = CryptoEngine.utf8ToChars(titleBytes);
                    iconChars = CryptoEngine.utf8ToChars(iconBytes);
                    command = CryptoEngine.utf8ToChars(commandBytes);
                    String title = new String(titleChars);
                    String icon = new String(iconChars);
                    validateMetadata(title, icon);
                    PortableEntry entry = new PortableEntry(title, icon, command,
                            (flags & 1) != 0, (flags & 2) != 0, (flags & 4) != 0);
                    validatePortableEntry(entry);
                    bundle.entries.add(entry);
                    command = null;
                } catch (CharacterCodingException exception) {
                    throw new VaultException("Backup data is invalid", exception);
                } finally {
                    CryptoEngine.wipe(titleBytes);
                    CryptoEngine.wipe(iconBytes);
                    CryptoEngine.wipe(commandBytes);
                    CryptoEngine.wipe(titleChars);
                    CryptoEngine.wipe(iconChars);
                    CryptoEngine.wipe(command);
                }
            }
            reader.requireEnd();
            return bundle;
        } catch (VaultException | RuntimeException exception) {
            bundle.wipe();
            if (exception instanceof VaultException vaultException) throw vaultException;
            throw invalidBackup(exception);
        }
    }

    private static Bundle decodeEncrypted(char[] text, char[] passphrase) throws VaultException {
        int start = skipWhitespace(text, 0, text.length);
        int bodyStart = start + ENCRYPTED_PREFIX.length();
        int end = trimWhitespaceEnd(text, bodyStart, text.length);
        int bodyLength = end - bodyStart;
        if (bodyLength <= 0 || bodyLength > 6 * 1024 * 1024 || bodyLength % 4 == 1) {
            throw invalidBackup();
        }

        byte[] encoded = null;
        byte[] envelope = null;
        byte[] salt = null;
        byte[] iv = null;
        byte[] ciphertext = null;
        byte[] key = null;
        byte[] payload = null;
        CryptoEngine.Blob blob = null;
        try {
            encoded = new byte[bodyLength];
            for (int index = 0; index < bodyLength; index++) {
                char value = text[bodyStart + index];
                if (!isUnpaddedBase64(value)) throw invalidBackup();
                encoded[index] = (byte) value;
            }
            envelope = Base64.getDecoder().decode(encoded);
            ByteReader reader = new ByteReader(envelope);
            reader.expect(ENVELOPE_MAGIC);
            if (reader.readInt() != FORMAT_VERSION) throw invalidBackup();
            int memoryKiB = reader.readInt();
            int iterations = reader.readInt();
            int parallelism = reader.readInt();
            if (!isSupportedArgon2(memoryKiB, iterations, parallelism)) throw invalidBackup();
            salt = reader.readFixed(SALT_BYTES);
            iv = reader.readFixed(CryptoEngine.GCM_IV_BYTES);
            ciphertext = reader.readLengthPrefixed(MAX_PAYLOAD_BYTES + 16);
            if (ciphertext.length < 16) throw invalidBackup();
            reader.requireEnd();

            key = CryptoEngine.deriveArgon2id(passphrase, salt, memoryKiB, iterations, parallelism);
            blob = new CryptoEngine.Blob(iv, ciphertext);
            iv = null;
            ciphertext = null;
            payload = CryptoEngine.decrypt(key, blob, BACKUP_AAD);
            return decodePayload(payload);
        } catch (AEADBadTagException exception) {
            throw new VaultException(
                    "Backup passphrase is incorrect or the encrypted backup is damaged", exception);
        } catch (VaultException exception) {
            throw exception;
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw invalidBackup(exception);
        } finally {
            CryptoEngine.wipe(encoded);
            CryptoEngine.wipe(envelope);
            CryptoEngine.wipe(salt);
            CryptoEngine.wipe(iv);
            CryptoEngine.wipe(ciphertext);
            CryptoEngine.wipe(key);
            CryptoEngine.wipe(payload);
            if (blob != null) blob.wipe();
        }
    }

    private static Bundle decodePlaintext(char[] text) throws VaultException {
        JsonParser parser = new JsonParser(text);
        Bundle bundle = null;
        byte[] validatedPayload = null;
        try {
            parser.expect('{');
            parser.expectName("format");
            parser.expect(':');
            parser.expectStringValue(PLAINTEXT_FORMAT, 64);
            parser.expect(',');
            parser.expectName("version");
            parser.expect(':');
            if (parser.readNonnegativeInt() != FORMAT_VERSION) throw invalidBackup();
            parser.expect(',');
            parser.expectName("protection");
            parser.expect(':');
            parser.expectStringValue("none", 16);
            parser.expect(',');
            parser.expectName("entries");
            parser.expect(':');
            bundle = parser.readEntries();
            parser.expect('}');
            parser.requireEnd();

            // Plaintext JSON intentionally has no cryptographic integrity. This checks only the
            // complete schema, every field, and the aggregate portable-payload size.
            validatedPayload = encodePayload(bundle);
            Bundle result = bundle;
            bundle = null;
            return result;
        } catch (VaultException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw invalidBackup(exception);
        } finally {
            if (bundle != null) bundle.wipe();
            CryptoEngine.wipe(validatedPayload);
        }
    }

    private static void writePlaintextJson(CharWriter output, Bundle bundle)
            throws VaultException {
        output.put("{\n");
        output.put("  \"format\": ");
        output.putJsonString(PLAINTEXT_FORMAT);
        output.put(",\n  \"version\": 1,\n  \"protection\": \"none\"");
        output.put(",\n  \"entries\": [");
        if (!bundle.entries.isEmpty()) output.put('\n');
        for (int index = 0; index < bundle.entries.size(); index++) {
            PortableEntry entry = bundle.entries.get(index);
            output.put("    {\n      \"title\": ");
            output.putJsonString(entry.title);
            output.put(",\n      \"icon\": ");
            output.putJsonString(entry.icon);
            output.put(",\n      \"command\": ");
            output.putJsonString(entry.command);
            output.put(",\n      \"pause_after_run\": ");
            output.put(entry.pauseAfterRun ? "true" : "false");
            output.put(",\n      \"notify_when_finished\": ");
            output.put(entry.notifyWhenFinished ? "true" : "false");
            output.put(",\n      \"hide_terminal_output\": ");
            output.put(entry.hideTerminalOutput ? "true" : "false");
            output.put("\n    }");
            output.put(index + 1 == bundle.entries.size() ? "\n" : ",\n");
        }
        output.put(bundle.entries.isEmpty() ? "]\n}\n" : "  ]\n}\n");
    }

    private static void validatePortableEntry(PortableEntry entry) throws VaultException {
        if (entry == null || entry.command == null) throw invalidBackup();
        validateMetadata(entry.title, entry.icon);
        byte[] command = null;
        try {
            command = CryptoEngine.charsToUtf8(entry.command);
            if (command.length == 0 || command.length > VaultService.MAX_COMMAND_BYTES
                    || containsNul(command)) throw invalidBackup();
        } catch (CharacterCodingException exception) {
            throw invalidBackup(exception);
        } finally {
            CryptoEngine.wipe(command);
        }
    }

    private static void validateMetadata(String title, String icon) throws VaultException {
        if (TextPolicy.isBlank(title) || title.length() > 80
                || icon == null || !EntryIcons.isKnown(icon)) throw invalidBackup();
        try {
            byte[] titleBytes = strictUtf8(title);
            CryptoEngine.wipe(titleBytes);
        } catch (CharacterCodingException exception) {
            throw invalidBackup(exception);
        }
    }

    private static byte[] strictUtf8(String value) throws CharacterCodingException {
        char[] chars = value.toCharArray();
        try {
            return CryptoEngine.charsToUtf8(chars);
        } finally {
            CryptoEngine.wipe(chars);
        }
    }

    private static void requireVmk(byte[] vmk) throws VaultException {
        if (vmk == null || vmk.length != CryptoEngine.KEY_BYTES) {
            throw new VaultException("Vault key is invalid");
        }
    }

    private static void requireBackupPassphrase(char[] passphrase) throws VaultException {
        PassphraseWarning.requireBackupPassphrase(passphrase);
    }

    private static int hexValue(char value) {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    }

    private static char[] prefixedAscii(String prefix, byte[] ascii) throws VaultException {
        if (ascii.length > 6 * 1024 * 1024) throw invalidBackup();
        char[] output = new char[prefix.length() + ascii.length];
        prefix.getChars(0, prefix.length(), output, 0);
        for (int index = 0; index < ascii.length; index++) {
            int value = ascii[index] & 0xff;
            if (value > 0x7f) {
                CryptoEngine.wipe(output);
                throw invalidBackup();
            }
            output[prefix.length() + index] = (char) value;
        }
        return output;
    }

    private static boolean containsNul(byte[] bytes) {
        for (byte value : bytes) if (value == 0) return true;
        return false;
    }

    private static boolean isUnpaddedBase64(char value) {
        return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
                || (value >= '0' && value <= '9') || value == '+' || value == '/';
    }

    /** Matches vault-file KDF bounds so older encrypted backups remain importable. */
    private static boolean isSupportedArgon2(int memoryKiB, int iterations, int parallelism) {
        return memoryKiB >= 32 * 1024 && memoryKiB <= 256 * 1024
                && iterations >= 1 && iterations <= 10
                && parallelism >= 1 && parallelism <= 4;
    }

    private static int skipWhitespace(char[] value, int start, int end) {
        int index = start;
        while (index < end && isJsonWhitespace(value[index])) index++;
        return index;
    }

    private static int trimWhitespaceEnd(char[] value, int start, int end) {
        int index = end;
        while (index > start && isJsonWhitespace(value[index - 1])) index--;
        return index;
    }

    private static boolean isJsonWhitespace(char value) {
        return value == ' ' || value == '\t' || value == '\r' || value == '\n';
    }

    private static boolean regionMatches(char[] value, int start, String expected) {
        if (start < 0 || value.length - start < expected.length()) return false;
        for (int index = 0; index < expected.length(); index++) {
            if (value[start + index] != expected.charAt(index)) return false;
        }
        return true;
    }

    private static VaultException invalidBackup() {
        return new VaultException("Backup data is invalid");
    }

    private static VaultException invalidBackup(Throwable cause) {
        return new VaultException("Backup data is invalid", cause);
    }

    static final class Bundle {
        private final List<PortableEntry> entries = new ArrayList<>();
        private boolean wiped;

        int size() {
            return wiped ? 0 : entries.size();
        }

        void wipe() {
            if (wiped) return;
            wiped = true;
            for (PortableEntry entry : entries) entry.wipe();
            entries.clear();
        }
    }

    private static final class PortableEntry {
        final String title;
        final String icon;
        char[] command;
        final boolean pauseAfterRun;
        final boolean notifyWhenFinished;
        final boolean hideTerminalOutput;

        PortableEntry(String title, String icon, char[] command, boolean pauseAfterRun,
                      boolean notifyWhenFinished, boolean hideTerminalOutput) {
            this.title = title;
            this.icon = icon;
            this.command = command;
            this.pauseAfterRun = pauseAfterRun;
            this.notifyWhenFinished = notifyWhenFinished;
            this.hideTerminalOutput = hideTerminalOutput;
        }

        void wipe() {
            CryptoEngine.wipe(command);
            command = null;
        }
    }

    private static final class ByteWriter {
        private final int limit;
        private byte[] buffer = new byte[256];
        private int size;

        ByteWriter(int limit) {
            this.limit = limit;
        }

        void putByte(int value) throws VaultException {
            ensure(1);
            buffer[size++] = (byte) value;
        }

        void putInt(int value) throws VaultException {
            if (value < 0) throw invalidBackup();
            ensure(4);
            buffer[size++] = (byte) (value >>> 24);
            buffer[size++] = (byte) (value >>> 16);
            buffer[size++] = (byte) (value >>> 8);
            buffer[size++] = (byte) value;
        }

        void putBytes(byte[] value) throws VaultException {
            if (value == null) throw invalidBackup();
            ensure(value.length);
            System.arraycopy(value, 0, buffer, size, value.length);
            size += value.length;
        }

        byte[] copy() {
            return Arrays.copyOf(buffer, size);
        }

        void wipe() {
            CryptoEngine.wipe(buffer);
            size = 0;
        }

        private void ensure(int additional) throws VaultException {
            if (additional < 0 || size > limit - additional) {
                throw new VaultException("Backup data is too large");
            }
            int required = size + additional;
            if (required <= buffer.length) return;
            int capacity = buffer.length;
            while (capacity < required) {
                int grown = capacity + Math.max(256, capacity / 2);
                capacity = Math.min(limit, grown);
                if (capacity < required && capacity == limit) {
                    throw new VaultException("Backup data is too large");
                }
            }
            byte[] replacement = Arrays.copyOf(buffer, capacity);
            CryptoEngine.wipe(buffer);
            buffer = replacement;
        }
    }

    private static final class ByteReader {
        private final byte[] input;
        private int position;

        ByteReader(byte[] input) {
            this.input = input;
        }

        void expect(byte[] expected) throws VaultException {
            require(expected.length);
            for (byte value : expected) if (input[position++] != value) throw invalidBackup();
        }

        int readInt() throws VaultException {
            require(4);
            int value = ((input[position] & 0xff) << 24)
                    | ((input[position + 1] & 0xff) << 16)
                    | ((input[position + 2] & 0xff) << 8)
                    | (input[position + 3] & 0xff);
            position += 4;
            if (value < 0) throw invalidBackup();
            return value;
        }

        int readUnsignedByte() throws VaultException {
            require(1);
            return input[position++] & 0xff;
        }

        byte[] readFixed(int length) throws VaultException {
            if (length < 0) throw invalidBackup();
            require(length);
            byte[] output = Arrays.copyOfRange(input, position, position + length);
            position += length;
            return output;
        }

        byte[] readLengthPrefixed(int maximum) throws VaultException {
            int length = readInt();
            if (length > maximum) throw invalidBackup();
            return readFixed(length);
        }

        void requireEnd() throws VaultException {
            if (position != input.length) throw invalidBackup();
        }

        private void require(int length) throws VaultException {
            if (length < 0 || position > input.length - length) throw invalidBackup();
        }
    }

    private static final class CharWriter {
        private final int limit;
        private char[] buffer = new char[256];
        private int size;

        CharWriter(int limit) {
            this.limit = limit;
        }

        void put(char value) throws VaultException {
            ensure(1);
            buffer[size++] = value;
        }

        void put(String value) throws VaultException {
            ensure(value.length());
            value.getChars(0, value.length(), buffer, size);
            size += value.length();
        }

        void put(char[] value) throws VaultException {
            ensure(value.length);
            System.arraycopy(value, 0, buffer, size, value.length);
            size += value.length;
        }

        void putJsonString(String value) throws VaultException {
            putJsonString(value, null);
        }

        void putJsonString(char[] value) throws VaultException {
            putJsonString(null, value);
        }

        private void putJsonString(String string, char[] chars) throws VaultException {
            int length = string != null ? string.length() : chars.length;
            put('"');
            for (int index = 0; index < length; index++) {
                char value = string != null ? string.charAt(index) : chars[index];
                switch (value) {
                    case '"' -> put("\\\"");
                    case '\\' -> put("\\\\");
                    case '\b' -> put("\\b");
                    case '\f' -> put("\\f");
                    case '\n' -> put("\\n");
                    case '\r' -> put("\\r");
                    case '\t' -> put("\\t");
                    default -> {
                        if (value < 0x20) {
                            put("\\u00");
                            put("0123456789abcdef".charAt((value >>> 4) & 0x0f));
                            put("0123456789abcdef".charAt(value & 0x0f));
                        } else if (Character.isHighSurrogate(value)) {
                            if (index + 1 >= length) throw invalidBackup();
                            char low = string != null ? string.charAt(index + 1) : chars[index + 1];
                            if (!Character.isLowSurrogate(low)) throw invalidBackup();
                            put(value);
                            put(low);
                            index++;
                        } else if (Character.isLowSurrogate(value)) {
                            throw invalidBackup();
                        } else {
                            put(value);
                        }
                    }
                }
            }
            put('"');
        }

        char[] copy() {
            return Arrays.copyOf(buffer, size);
        }

        void wipe() {
            CryptoEngine.wipe(buffer);
            size = 0;
        }

        private void ensure(int additional) throws VaultException {
            if (additional < 0 || size > limit - additional) {
                throw new VaultException("Backup text is too large");
            }
            int required = size + additional;
            if (required <= buffer.length) return;
            int capacity = buffer.length;
            while (capacity < required) {
                int grown = capacity + Math.max(256, capacity / 2);
                capacity = Math.min(limit, grown);
                if (capacity < required && capacity == limit) {
                    throw new VaultException("Backup text is too large");
                }
            }
            char[] replacement = Arrays.copyOf(buffer, capacity);
            CryptoEngine.wipe(buffer);
            buffer = replacement;
        }
    }

    private static final class JsonParser {
        private final char[] input;
        private int position;

        JsonParser(char[] input) throws VaultException {
            if (input == null || input.length == 0 || input.length > MAX_BACKUP_TEXT_CHARS) {
                throw invalidBackup();
            }
            this.input = input;
        }

        void expect(char expected) throws VaultException {
            whitespace();
            if (position >= input.length || input[position++] != expected) throw invalidBackup();
        }

        void expectName(String expected) throws VaultException {
            char[] actual = readString(Math.max(64, expected.length()));
            try {
                if (!equalsChars(actual, expected)) throw invalidBackup();
            } finally {
                CryptoEngine.wipe(actual);
            }
        }

        void expectStringValue(String expected, int maximum) throws VaultException {
            char[] actual = readString(maximum);
            try {
                if (!equalsChars(actual, expected)) throw invalidBackup();
            } finally {
                CryptoEngine.wipe(actual);
            }
        }

        int readNonnegativeInt() throws VaultException {
            whitespace();
            if (position >= input.length || input[position] < '0' || input[position] > '9') {
                throw invalidBackup();
            }
            int value = 0;
            int digits = 0;
            while (position < input.length && input[position] >= '0' && input[position] <= '9') {
                int digit = input[position++] - '0';
                if (value > (Integer.MAX_VALUE - digit) / 10) throw invalidBackup();
                value = value * 10 + digit;
                digits++;
            }
            if (digits > 1 && input[position - digits] == '0') throw invalidBackup();
            return value;
        }

        Bundle readEntries() throws VaultException {
            Bundle bundle = new Bundle();
            try {
                expect('[');
                whitespace();
                if (takeIf(']')) return bundle;
                while (true) {
                    if (bundle.entries.size() >= VaultStore.MAX_ENTRIES) throw invalidBackup();
                    bundle.entries.add(readEntry());
                    whitespace();
                    if (takeIf(']')) return bundle;
                    expect(',');
                }
            } catch (VaultException | RuntimeException exception) {
                bundle.wipe();
                if (exception instanceof VaultException vaultException) throw vaultException;
                throw invalidBackup(exception);
            }
        }

        private PortableEntry readEntry() throws VaultException {
            char[] titleChars = null;
            char[] iconChars = null;
            char[] command = null;
            try {
                expect('{');
                expectName("title");
                expect(':');
                titleChars = readString(80);
                expect(',');
                expectName("icon");
                expect(':');
                iconChars = readString(32);
                expect(',');
                expectName("command");
                expect(':');
                command = readString(VaultService.MAX_COMMAND_BYTES);
                expect(',');
                expectName("pause_after_run");
                expect(':');
                boolean pause = readBoolean();
                expect(',');
                expectName("notify_when_finished");
                expect(':');
                boolean notify = readBoolean();
                expect(',');
                expectName("hide_terminal_output");
                expect(':');
                boolean hide = readBoolean();
                expect('}');
                String title = new String(titleChars);
                String icon = new String(iconChars);
                PortableEntry entry = new PortableEntry(title, icon, command, pause, notify, hide);
                validatePortableEntry(entry);
                command = null;
                return entry;
            } finally {
                CryptoEngine.wipe(titleChars);
                CryptoEngine.wipe(iconChars);
                CryptoEngine.wipe(command);
            }
        }

        char[] readString(int maximumChars) throws VaultException {
            whitespace();
            if (maximumChars < 0 || position >= input.length || input[position++] != '"') {
                throw invalidBackup();
            }
            CharWriter output = new CharWriter(maximumChars);
            boolean closed = false;
            try {
                while (position < input.length) {
                    char value = input[position++];
                    if (value == '"') {
                        closed = true;
                        break;
                    }
                    if (value < 0x20) throw invalidBackup();
                    if (value != '\\') {
                        output.put(value);
                        continue;
                    }
                    if (position >= input.length) throw invalidBackup();
                    char escaped = input[position++];
                    switch (escaped) {
                        case '"', '\\', '/' -> output.put(escaped);
                        case 'b' -> output.put('\b');
                        case 'f' -> output.put('\f');
                        case 'n' -> output.put('\n');
                        case 'r' -> output.put('\r');
                        case 't' -> output.put('\t');
                        case 'u' -> output.put(readUnicodeEscape());
                        default -> throw invalidBackup();
                    }
                }
                if (!closed) throw invalidBackup();
                char[] result = output.copy();
                try {
                    validateUtf16(result);
                    return result;
                } catch (VaultException exception) {
                    CryptoEngine.wipe(result);
                    throw exception;
                }
            } finally {
                output.wipe();
            }
        }

        private char readUnicodeEscape() throws VaultException {
            if (position > input.length - 4) throw invalidBackup();
            int value = 0;
            for (int index = 0; index < 4; index++) {
                int digit = hexValue(input[position++]);
                if (digit < 0) throw invalidBackup();
                value = (value << 4) | digit;
            }
            return (char) value;
        }

        private boolean readBoolean() throws VaultException {
            whitespace();
            if (regionMatches(input, position, "true")) {
                position += 4;
                return true;
            }
            if (regionMatches(input, position, "false")) {
                position += 5;
                return false;
            }
            throw invalidBackup();
        }

        void requireEnd() throws VaultException {
            whitespace();
            if (position != input.length) throw invalidBackup();
        }

        private boolean takeIf(char expected) {
            if (position < input.length && input[position] == expected) {
                position++;
                return true;
            }
            return false;
        }

        private void whitespace() {
            position = skipWhitespace(input, position, input.length);
        }
    }

    private static void validateUtf16(char[] value) throws VaultException {
        for (int index = 0; index < value.length; index++) {
            char current = value[index];
            if (Character.isHighSurrogate(current)) {
                if (++index >= value.length || !Character.isLowSurrogate(value[index])) {
                    throw invalidBackup();
                }
            } else if (Character.isLowSurrogate(current)) {
                throw invalidBackup();
            }
        }
    }

    private static boolean equalsChars(char[] value, String expected) {
        if (value.length != expected.length()) return false;
        for (int index = 0; index < value.length; index++) {
            if (value[index] != expected.charAt(index)) return false;
        }
        return true;
    }
}
