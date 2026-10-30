package app.termuxvault.secure;

import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.os.PersistableBundle;
import android.text.Editable;
import android.widget.EditText;

/** Centralizes sensitive clipboard metadata so no copy path can omit it accidentally. */
final class SensitiveClipboard {
    /* ClipDescription.EXTRA_IS_SENSITIVE, written as a literal so it is safe below API 33. */
    private static final String EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE";

    private SensitiveClipboard() {}

    static ClipData plainText(CharSequence label, CharSequence text) {
        ClipData clip = ClipData.newPlainText(label, text);
        ClipDescription description = clip.getDescription();
        PersistableBundle existing = description.getExtras();
        PersistableBundle extras = existing == null
                ? new PersistableBundle() : new PersistableBundle(existing);
        extras.putBoolean(EXTRA_IS_SENSITIVE, true);
        description.setExtras(extras);
        return clip;
    }

    /**
     * Copies the current selection and optionally removes it. A failed clipboard write is
     * consumed by the caller but never removes editor text or falls back to an unmarked clip.
     */
    static boolean copySelection(EditText field, boolean cut) {
        Editable editable = field.getText();
        if (editable == null) return false;

        Range range = Range.of(field.getSelectionStart(), field.getSelectionEnd(),
                editable.length());
        if (range == null) return false;

        ClipboardManager clipboard = field.getContext().getSystemService(ClipboardManager.class);
        if (clipboard == null) return false;

        // SpannableStringBuilder.subSequence() creates an independent CharSequence, so a cut
        // cannot mutate the ClipData after Android accepts it.
        CharSequence selected = editable.subSequence(range.start, range.end);
        try {
            clipboard.setPrimaryClip(plainText("Sensitive text", selected));
        } catch (RuntimeException exception) {
            return false;
        }

        if (cut) {
            field.beginBatchEdit();
            try {
                editable.delete(range.start, range.end);
            } finally {
                field.endBatchEdit();
            }
        }
        return true;
    }

    static final class Range {
        final int start;
        final int end;

        private Range(int start, int end) {
            this.start = start;
            this.end = end;
        }

        static Range of(int first, int second, int length) {
            if (first < 0 || second < 0 || length < 0) return null;
            int start = Math.min(first, second);
            int end = Math.max(first, second);
            if (start == end || end > length) return null;
            return new Range(start, end);
        }
    }
}
