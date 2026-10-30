package app.termuxvault.secure;

final class CommandEditorPolicy {
    private CommandEditorPolicy() {}

    static boolean blocks(int itemId, String intentAction) {
        return itemId == android.R.id.copyUrl
                || itemId == android.R.id.shareText
                || itemId == android.R.id.autofill
                || itemId == android.R.id.textAssist
                || itemId == android.R.id.replaceText
                || intentAction != null;
    }
}
