package app.termuxvault.secure;

import android.content.Context;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;

final class PasswordInput extends LinearLayout {
    private final EditText field;
    private final ImageButton toggle;
    private boolean visible;

    PasswordInput(Context context) {
        this(context, "Vault passphrase");
    }

    PasswordInput(Context context, String hint) {
        super(context);
        setOrientation(HORIZONTAL);
        setGravity(Gravity.CENTER_VERTICAL);
        setSaveEnabled(false);
        setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        setImportantForContentCapture(
                View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS);

        field = Ui.textField(context, hint, true);
        field.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                | EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        field.setTransformationMethod(PasswordTransformationMethod.getInstance());
        addView(field, new LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));

        toggle = new ImageButton(context);
        toggle.setBackgroundColor(Ui.BACKGROUND);
        TypedValue selectable = new TypedValue();
        if (context.getTheme().resolveAttribute(
                android.R.attr.selectableItemBackgroundBorderless, selectable, true)
                && selectable.resourceId != 0) {
            toggle.setBackgroundResource(selectable.resourceId);
        }
        toggle.setColorFilter(Ui.MUTED);
        toggle.setPadding(Ui.dp(context, 12), Ui.dp(context, 12),
                Ui.dp(context, 12), Ui.dp(context, 12));
        toggle.setSaveEnabled(false);
        toggle.setFocusable(false);
        toggle.setFocusableInTouchMode(false);
        toggle.setFilterTouchesWhenObscured(true);
        toggle.setOnClickListener(view -> setPasswordVisible(!visible));
        addView(toggle, new LayoutParams(Ui.dp(context, 48), Ui.dp(context, 48)));
        updateToggle();
    }

    EditText editText() {
        return field;
    }

    void setImeOptions(int options) {
        field.setImeOptions(options);
    }

    void mask() {
        if (visible) setPasswordVisible(false);
    }

    private void setPasswordVisible(boolean show) {
        int start = field.getSelectionStart();
        int end = field.getSelectionEnd();
        visible = show;
        field.setTransformationMethod(show
                ? HideReturnsTransformationMethod.getInstance()
                : PasswordTransformationMethod.getInstance());
        if (start >= 0 && end >= 0) field.setSelection(start, end);
        updateToggle();
    }

    private void updateToggle() {
        toggle.setImageResource(visible
                ? R.drawable.ic_visibility_off : R.drawable.ic_visibility);
        toggle.setContentDescription(visible ? "Hide passphrase" : "Show passphrase");
    }

    @Override
    public void onWindowFocusChanged(boolean hasWindowFocus) {
        super.onWindowFocusChanged(hasWindowFocus);
        if (!hasWindowFocus && visible) setPasswordVisible(false);
    }

    @Override
    protected void onDetachedFromWindow() {
        if (visible) setPasswordVisible(false);
        super.onDetachedFromWindow();
    }
}
