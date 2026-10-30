package app.termuxvault.secure;

final class SecureTextActionPolicy {
    private SecureTextActionPolicy() {}

    static boolean blocks(int itemId, String intentAction) {
        return itemId == android.R.id.copy
                || itemId == android.R.id.copyUrl
                || itemId == android.R.id.cut
                || itemId == android.R.id.shareText
                || itemId == android.R.id.autofill
                || itemId == android.R.id.textAssist
                || itemId == android.R.id.replaceText
                // Android and OEMs may add external processors with actions other than the
                // standard PROCESS_TEXT/SEND values. No intent-backed action may receive a
                // passphrase; local Paste, Select all, and the eye toggle do not use one.
                || intentAction != null;
    }
}
