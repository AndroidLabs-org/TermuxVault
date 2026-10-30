package app.termuxvault.secure;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build;
import android.text.Editable;
import android.text.InputType;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.RelativeSizeSpan;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.Window;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.nio.CharBuffer;

final class Ui {
    static final int BACKGROUND = Color.rgb(16, 20, 24);
    static final int SURFACE = Color.rgb(26, 34, 41);
    static final int TEXT = Color.rgb(242, 247, 247);
    static final int MUTED = Color.rgb(168, 183, 184);
    static final int ACCENT = Color.rgb(86, 214, 201);
    static final int DANGER = Color.rgb(255, 113, 113);

    private Ui() {}

    static int dp(Context context, int value) {
        return Math.round(value * context.getResources().getDisplayMetrics().density);
    }

    static LinearLayout page(Context context) {
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(dp(context, 20), dp(context, 18), dp(context, 20), dp(context, 18));
        layout.setBackgroundColor(BACKGROUND);
        layout.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        return layout;
    }

    static TextView title(Context context, String value) {
        TextView view = text(context, value, 26, TEXT);
        view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        view.setAccessibilityHeading(true);
        view.setPadding(0, 0, 0, dp(context, 10));
        return view;
    }

    static TextView heading(Context context, String value, int sp, int color) {
        TextView view = text(context, value, sp, color);
        view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        view.setAccessibilityHeading(true);
        return view;
    }

    static TextView text(Context context, String value, int sp, int color) {
        TextView view = new TextView(context);
        view.setText(value);
        view.setTextSize(sp);
        view.setTextColor(color);
        if (value.isEmpty()) {
            // Empty TextViews are the app's generic asynchronous status/error slots. Their
            // messages never contain passphrases or command text, so polite announcements are
            // useful without exposing protected content.
            view.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        }
        return view;
    }

    static Button button(Context context, String label) {
        Button button = new Button(context);
        button.setText(label);
        button.setTextSize(14);
        button.setTextColor(TEXT);
        button.setAllCaps(false);
        button.setBackgroundResource(R.drawable.button_background);
        button.setMinWidth(dp(context, 48));
        button.setMinHeight(dp(context, 48));
        button.setPadding(dp(context, 14), dp(context, 8),
                dp(context, 14), dp(context, 8));
        button.setFilterTouchesWhenObscured(true);
        return button;
    }

    static EditText textField(Context context, String hint, boolean sensitive) {
        EditText field = sensitive ? new SecureEditText(context) : new EditText(context);
        setCompactHint(field, hint);
        field.setHintTextColor(MUTED);
        field.setTextColor(TEXT);
        field.setSingleLine(true);
        field.setSelectAllOnFocus(false);
        field.setSaveEnabled(false);
        field.setLongClickable(true);
        field.setTextIsSelectable(!sensitive);
        field.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        field.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                | EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        if (sensitive) {
            field.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD
                    | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        }
        return field;
    }

    static void setCompactHint(EditText field, String hint) {
        SpannableString compact = new SpannableString(hint);
        compact.setSpan(new RelativeSizeSpan(0.82f), 0, compact.length(),
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        field.setHint(compact);
    }

    static char[] readChars(EditText field) {
        Editable value = field.getText();
        char[] chars = new char[value.length()];
        value.getChars(0, value.length(), chars, 0);
        return chars;
    }

    static void clear(EditText field) {
        Editable editable = field.getText();
        if (editable == null) return;
        char[] zeros = new char[editable.length()];
        if (zeros.length > 0) editable.replace(0, editable.length(), CharBuffer.wrap(zeros));
        CryptoEngine.wipe(zeros);
        editable.clear();
        ViewParent parent = field.getParent();
        if (parent instanceof PasswordInput passwordInput) passwordInput.mask();
    }

    static void addSpace(LinearLayout layout, int dp) {
        View space = new View(layout.getContext());
        layout.addView(space, new LinearLayout.LayoutParams(1, Ui.dp(layout.getContext(), dp)));
    }

    static void showError(Activity activity, String message) {
        if (activity.isFinishing() || activity.isDestroyed()) return;
        showSecure(new AlertDialog.Builder(activity)
                .setTitle("Termux Vault")
                .setMessage(message)
                .setPositiveButton("OK", null));
    }

    /** Dialogs have their own Window, so activity-level capture/overlay protection is not inherited. */
    static AlertDialog createSecure(AlertDialog.Builder builder) {
        AlertDialog dialog = builder.create();
        secure(dialog);
        return dialog;
    }

    static void showSecure(AlertDialog.Builder builder) {
        AlertDialog dialog = createSecure(builder);
        dialog.show();
    }

    static void showSecure(AlertDialog dialog) {
        secure(dialog);
        dialog.show();
    }

    private static void secure(AlertDialog dialog) {
        Window window = dialog.getWindow();
        if (window == null) return;
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        window.getDecorView().setFilterTouchesWhenObscured(true);
        if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true);
        SecureActivity.installSelectionDismissal(dialog.getContext(), window);
    }

    static LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }
}
