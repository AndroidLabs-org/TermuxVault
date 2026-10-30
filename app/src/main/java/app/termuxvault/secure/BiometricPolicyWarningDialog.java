package app.termuxvault.secure;

import android.app.AlertDialog;
import android.graphics.Typeface;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** Shared two-level warning UI; technical policy values are hidden until explicitly requested. */
final class BiometricPolicyWarningDialog {
    interface Callback {
        void onContinue();

        void onDecline();

        void onCancel();
    }

    private BiometricPolicyWarningDialog() {}

    static AlertDialog create(SecureActivity activity,
                              BiometricKeyPolicy.PolicyReport report,
                              String actionReason,
                              String additionalGuidance,
                              String continueLabel,
                              String declineLabel,
                              Callback callback) {
        LinearLayout body = new LinearLayout(activity);
        body.setOrientation(LinearLayout.VERTICAL);
        int horizontal = Ui.dp(activity, 20);
        body.setPadding(horizontal, Ui.dp(activity, 4), horizontal, Ui.dp(activity, 4));
        body.addView(Ui.text(activity, report.friendlyWarningMessage(actionReason),
                14, Ui.MUTED), Ui.matchWrap());
        if (additionalGuidance != null && !additionalGuidance.isEmpty()) {
            Ui.addSpace(body, 8);
            body.addView(Ui.text(activity, additionalGuidance, 14, Ui.MUTED), Ui.matchWrap());
        }

        TextView technical = Ui.text(activity, report.technicalDetails(), 12, Ui.MUTED);
        technical.setTypeface(Typeface.MONOSPACE);
        technical.setVisibility(View.GONE);
        Ui.addSpace(body, 8);
        body.addView(technical, Ui.matchWrap());

        ScrollView scroll = new ScrollView(activity);
        scroll.addView(body);
        AlertDialog dialog = Ui.createSecure(new AlertDialog.Builder(activity)
                .setTitle("Biometric protection not fully verified")
                .setView(scroll)
                .setPositiveButton(continueLabel,
                        (ignored, which) -> callback.onContinue())
                .setNegativeButton(declineLabel,
                        (ignored, which) -> callback.onDecline())
                .setNeutralButton("Technical details", null)
                .setOnCancelListener(ignored -> callback.onCancel()));
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_NEUTRAL)
                .setOnClickListener(view -> {
                    boolean show = technical.getVisibility() != View.VISIBLE;
                    technical.setVisibility(show ? View.VISIBLE : View.GONE);
                    dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setText(
                            show ? "Hide technical details" : "Technical details");
                }));
        return dialog;
    }
}
