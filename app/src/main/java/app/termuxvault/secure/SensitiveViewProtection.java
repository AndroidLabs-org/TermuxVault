package app.termuxvault.secure;

import android.os.Build;
import android.view.View;
import android.view.ViewStructure;
import android.view.textclassifier.TextClassifier;
import android.widget.EditText;

final class SensitiveViewProtection {
    private SensitiveViewProtection() {}

    static void configure(EditText field) {
        SecureActivity.registerSensitiveText(field);
        field.setSaveEnabled(false);
        field.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        field.setImportantForContentCapture(
                View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS);
        field.setTextClassifier(TextClassifier.NO_OP);
        if (Build.VERSION.SDK_INT >= 34) {
            field.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES);
        }
    }

    static void redactStructure(ViewStructure structure) {
        // Do not let a defensive fallback structure contain the live text or an autofill value.
        structure.setDataIsSensitive(true);
        structure.setText(null);
        structure.setHint(null);
        structure.setContentDescription(null);
        structure.setAutofillType(View.AUTOFILL_TYPE_NONE);
        structure.setAutofillHints(null);
        structure.setAutofillOptions(null);
        structure.setAutofillValue(null);
        structure.setChildCount(0);
    }
}
