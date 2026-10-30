package app.termuxvault.secure;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

@SuppressLint("ApplySharedPref") // Completion tokens must be durable/consumed before either process can exit.
final class CompletionStore {
    static final class Request {
        final String id;
        final String token;

        Request(String id, String token) {
            this.id = id;
            this.token = token;
        }
    }

    static final class Record {
        final String title;

        Record(String title) {
            this.title = title;
        }
    }

    private static final String PREFERENCES = "completion-requests";
    private static final int MAX_PENDING = 64;
    private static final Object LOCK = new Object();

    private CompletionStore() {}

    static Request prepare(Context context, String title) throws VaultException {
        if (title == null || title.isEmpty() || title.length() > 80) {
            throw new VaultException("Completion notification data is invalid");
        }
        byte[] idBytes = CryptoEngine.randomBytes(CompletionAuth.RUN_ID_BYTES);
        byte[] tokenBytes = CryptoEngine.randomBytes(CompletionAuth.TOKEN_BYTES);
        byte[] tokenHash = null;
        try {
            String id = CompletionAuth.hex(idBytes);
            String token = CompletionAuth.hex(tokenBytes);
            tokenHash = CompletionAuth.hash(tokenBytes);
            JSONObject record = new JSONObject();
            record.put("created_at", System.currentTimeMillis());
            record.put("title", title);
            record.put("token_hash", CryptoEngine.toBase64(tokenHash));
            synchronized (LOCK) {
                SharedPreferences preferences = preferences(context);
                RecordScan scan = scan(preferences.getAll());
                if (scan.validCreatedAt.containsKey(id)) {
                    throw new VaultException("Completion notification could not be prepared");
                }
                SharedPreferences.Editor editor = preferences.edit();
                for (String invalidId : scan.invalidIds.keySet()) editor.remove(invalidId);

                // Completion records contain no command or plaintext secret. Keep them until they
                // are consumed, but bound storage by evicting the oldest valid request first.
                Map<String, Long> retained = new HashMap<>(scan.validCreatedAt);
                while (retained.size() >= MAX_PENDING) {
                    String oldestId = oldestRecordId(retained);
                    if (oldestId == null) break;
                    retained.remove(oldestId);
                    editor.remove(oldestId);
                }
                editor.putString(id, record.toString());
                if (!editor.commit()) {
                    throw new VaultException("Completion notification could not be prepared");
                }
            }
            return new Request(id, token);
        } catch (JSONException exception) {
            throw new VaultException("Completion notification could not be prepared", exception);
        } finally {
            CryptoEngine.wipe(idBytes);
            CryptoEngine.wipe(tokenBytes);
            CryptoEngine.wipe(tokenHash);
        }
    }

    static Record verifyAndConsume(Context context, String id, String token) {
        if (!CompletionAuth.isLowerHex(id, CompletionAuth.RUN_ID_BYTES)) return null;
        synchronized (LOCK) {
            SharedPreferences preferences = preferences(context);
            String encoded;
            try {
                encoded = preferences.getString(id, null);
            } catch (ClassCastException exception) {
                preferences.edit().remove(id).commit();
                return null;
            }
            if (encoded == null) return null;
            ParsedRecord parsed = parseRecord(encoded);
            if (parsed == null) {
                preferences.edit().remove(id).commit();
                return null;
            }
            try {
                if (!CompletionAuth.matches(parsed.tokenHash, token)) return null;
                if (!preferences.edit().remove(id).commit()) return null;
                return new Record(parsed.title);
            } finally {
                parsed.clear();
            }
        }
    }

    static void cancel(Context context, Request request) {
        if (request == null || !CompletionAuth.isLowerHex(
                request.id, CompletionAuth.RUN_ID_BYTES)) return;
        synchronized (LOCK) {
            preferences(context).edit().remove(request.id).commit();
        }
    }

    static void clearAll(Context context) throws VaultException {
        synchronized (LOCK) {
            try {
                if (!preferences(context).edit().clear().commit()) {
                    throw new VaultException("Completion notification state could not be cleared");
                }
            } catch (VaultException exception) {
                throw exception;
            } catch (RuntimeException exception) {
                throw new VaultException(
                        "Completion notification state could not be cleared", exception);
            }
        }
    }

    static void pruneInvalid(Context context) {
        synchronized (LOCK) {
            SharedPreferences preferences = preferences(context);
            RecordScan scan = scan(preferences.getAll());
            if (scan.invalidIds.isEmpty()) return;
            SharedPreferences.Editor editor = preferences.edit();
            for (String invalidId : scan.invalidIds.keySet()) editor.remove(invalidId);
            editor.commit();
        }
    }

    static String oldestRecordId(Map<String, Long> createdAtById) {
        String oldestId = null;
        long oldestTime = Long.MAX_VALUE;
        for (Map.Entry<String, Long> entry : createdAtById.entrySet()) {
            Long createdAt = entry.getValue();
            if (createdAt == null) continue;
            if (createdAt < oldestTime || (createdAt == oldestTime
                    && (oldestId == null || entry.getKey().compareTo(oldestId) < 0))) {
                oldestId = entry.getKey();
                oldestTime = createdAt;
            }
        }
        return oldestId;
    }

    private static RecordScan scan(Map<String, ?> values) {
        RecordScan result = new RecordScan();
        for (Map.Entry<String, ?> entry : values.entrySet()) {
            ParsedRecord parsed = null;
            if (CompletionAuth.isLowerHex(entry.getKey(), CompletionAuth.RUN_ID_BYTES)
                    && entry.getValue() instanceof String encoded) {
                parsed = parseRecord(encoded);
            }
            if (parsed == null) {
                result.invalidIds.put(entry.getKey(), Boolean.TRUE);
            } else {
                result.validCreatedAt.put(entry.getKey(), parsed.createdAt);
                parsed.clear();
            }
        }
        return result;
    }

    private static ParsedRecord parseRecord(String encoded) {
        try {
            JSONObject record = new JSONObject(encoded);
            long createdAt = record.getLong("created_at");
            String title = record.getString("title");
            String tokenHash = record.getString("token_hash");
            if (createdAt <= 0 || title.isEmpty() || title.length() > 80
                    || !isValidHash(tokenHash)) return null;
            return new ParsedRecord(createdAt, title, tokenHash);
        } catch (JSONException | ClassCastException | IllegalArgumentException exception) {
            return null;
        }
    }

    private static boolean isValidHash(String encoded) {
        byte[] hash = null;
        try {
            hash = CryptoEngine.fromBase64(encoded);
            return hash.length == 32;
        } catch (IllegalArgumentException exception) {
            return false;
        } finally {
            CryptoEngine.wipe(hash);
        }
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
    }

    private static final class ParsedRecord {
        final long createdAt;
        final String title;
        String tokenHash;

        ParsedRecord(long createdAt, String title, String tokenHash) {
            this.createdAt = createdAt;
            this.title = title;
            this.tokenHash = tokenHash;
        }

        void clear() {
            tokenHash = null;
        }
    }

    private static final class RecordScan {
        final Map<String, Long> validCreatedAt = new HashMap<>();
        final Map<String, Boolean> invalidIds = new HashMap<>();
    }
}
