package app.termuxvault.secure;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

final class VaultState {
    static final int CURRENT_VERSION = 1;

    int version = CURRENT_VERSION;
    String kdfSalt;
    int kdfMemoryKiB;
    int kdfIterations;
    int kdfParallelism;
    String passVmkIv;
    String passVmkCiphertext;
    String bioVmkIv;
    String bioVmkCiphertext;
    final List<String> bioPolicyAcknowledgements = new ArrayList<>();
    final List<Entry> entries = new ArrayList<>();
    final List<String> trustedTermuxCertificates = new ArrayList<>();

    JSONObject toJson() throws JSONException {
        JSONObject root = new JSONObject();
        root.put("version", version);
        JSONObject kdf = new JSONObject();
        kdf.put("algorithm", "argon2id");
        kdf.put("salt", kdfSalt);
        kdf.put("memory_kib", kdfMemoryKiB);
        kdf.put("iterations", kdfIterations);
        kdf.put("parallelism", kdfParallelism);
        root.put("kdf", kdf);

        JSONObject passWrap = new JSONObject();
        passWrap.put("iv", passVmkIv);
        passWrap.put("ciphertext", passVmkCiphertext);
        root.put("passphrase_vmk", passWrap);

        if (bioVmkIv != null && bioVmkCiphertext != null) {
            JSONObject bioWrap = new JSONObject();
            bioWrap.put("iv", bioVmkIv);
            bioWrap.put("ciphertext", bioVmkCiphertext);
            if (!bioPolicyAcknowledgements.isEmpty()) {
                JSONArray acknowledgements = new JSONArray();
                for (String token : bioPolicyAcknowledgements) acknowledgements.put(token);
                bioWrap.put("accepted_policy_deviations", acknowledgements);
            }
            root.put("biometric_vmk", bioWrap);
        }

        JSONArray entryArray = new JSONArray();
        for (Entry entry : entries) entryArray.put(entry.toJson());
        root.put("entries", entryArray);

        JSONArray certificates = new JSONArray();
        for (String certificate : trustedTermuxCertificates) certificates.put(certificate);
        root.put("trusted_termux_certificates", certificates);
        return root;
    }

    static VaultState fromJson(JSONObject root) throws JSONException {
        VaultState state = new VaultState();
        state.version = root.getInt("version");
        if (state.version != CURRENT_VERSION) throw new JSONException("Unsupported vault version");

        JSONObject kdf = root.getJSONObject("kdf");
        if (!"argon2id".equals(kdf.getString("algorithm"))) {
            throw new JSONException("Unsupported vault KDF");
        }
        state.kdfSalt = kdf.getString("salt");
        state.kdfMemoryKiB = kdf.getInt("memory_kib");
        state.kdfIterations = kdf.getInt("iterations");
        state.kdfParallelism = kdf.getInt("parallelism");

        JSONObject passWrap = root.getJSONObject("passphrase_vmk");
        state.passVmkIv = passWrap.getString("iv");
        state.passVmkCiphertext = passWrap.getString("ciphertext");

        JSONObject bioWrap = root.optJSONObject("biometric_vmk");
        if (bioWrap != null) {
            state.bioVmkIv = bioWrap.getString("iv");
            state.bioVmkCiphertext = bioWrap.getString("ciphertext");
            if (bioWrap.has("accepted_policy_deviations")) {
                JSONArray acknowledgements =
                        bioWrap.optJSONArray("accepted_policy_deviations");
                if (acknowledgements == null) {
                    throw new JSONException("Invalid biometric policy acknowledgements");
                }
                if (acknowledgements.length() > VaultStore.MAX_BIOMETRIC_POLICY_ACKNOWLEDGEMENTS) {
                    throw new JSONException("Too many biometric policy acknowledgements");
                }
                for (int i = 0; i < acknowledgements.length(); i++) {
                    state.bioPolicyAcknowledgements.add(acknowledgements.getString(i));
                }
                if (!BiometricKeyPolicy.areCanonicalAcceptanceTokens(
                        state.bioPolicyAcknowledgements,
                        VaultStore.MAX_BIOMETRIC_POLICY_ACKNOWLEDGEMENTS)) {
                    throw new JSONException("Invalid biometric policy acknowledgement");
                }
            }
        }

        JSONArray entryArray = root.getJSONArray("entries");
        if (entryArray.length() > VaultStore.MAX_ENTRIES) throw new JSONException("Too many entries");
        for (int i = 0; i < entryArray.length(); i++) {
            state.entries.add(Entry.fromJson(entryArray.getJSONObject(i)));
        }

        JSONArray certificates = root.optJSONArray("trusted_termux_certificates");
        if (certificates != null) {
            if (certificates.length() > 16) throw new JSONException("Too many certificates");
            for (int i = 0; i < certificates.length(); i++) {
                state.trustedTermuxCertificates.add(certificates.getString(i));
            }
        }
        return state;
    }

    Entry findEntry(String id) {
        if (id == null) return null;
        for (Entry entry : entries) if (id.equals(entry.id)) return entry;
        return null;
    }

    static final class Entry {
        String id;
        String title;
        String icon;
        String dekIv;
        String dekCiphertext;
        String commandIv;
        String commandCiphertext;
        boolean pauseAfterRun;
        boolean notifyWhenFinished;
        boolean hideTerminalOutput;
        long createdAt;
        long modifiedAt;

        JSONObject toJson() throws JSONException {
            JSONObject object = new JSONObject();
            object.put("id", id);
            object.put("title", title);
            object.put("icon", icon);
            object.put("dek_iv", dekIv);
            object.put("dek_ciphertext", dekCiphertext);
            object.put("command_iv", commandIv);
            object.put("command_ciphertext", commandCiphertext);
            object.put("pause_after_run", pauseAfterRun);
            object.put("notify_when_finished", notifyWhenFinished);
            object.put("hide_terminal_output", hideTerminalOutput);
            object.put("created_at", createdAt);
            object.put("modified_at", modifiedAt);
            return object;
        }

        static Entry fromJson(JSONObject object) throws JSONException {
            Entry entry = new Entry();
            entry.id = object.getString("id");
            entry.title = object.getString("title");
            entry.icon = object.getString("icon");
            entry.dekIv = object.getString("dek_iv");
            entry.dekCiphertext = object.getString("dek_ciphertext");
            entry.commandIv = object.getString("command_iv");
            entry.commandCiphertext = object.getString("command_ciphertext");
            entry.pauseAfterRun = object.has("pause_after_run")
                    && object.getBoolean("pause_after_run");
            entry.notifyWhenFinished = object.has("notify_when_finished")
                    && object.getBoolean("notify_when_finished");
            entry.hideTerminalOutput = object.has("hide_terminal_output")
                    && object.getBoolean("hide_terminal_output");
            entry.createdAt = object.getLong("created_at");
            entry.modifiedAt = object.getLong("modified_at");
            return entry;
        }
    }
}
