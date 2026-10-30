package app.termuxvault.secure;

import android.app.AlertDialog;

final class IdentityApproval {
    private IdentityApproval() {}

    static void show(SecureActivity activity, TermuxIdentity identity, boolean replacement,
                     Runnable approve, Runnable cancel) {
        String heading = replacement ? "Termux identity changed" : "Trust Termux installation";
        String explanation = replacement
                ? "The installed Termux certificate does not match the trusted installation. Verify this fingerprint before replacing trust."
                : "Verify and trust this Termux signing certificate. Future unrelated replacements will be blocked.";
        String details = explanation + "\n\n" + identity.displayDetails();
        Ui.showSecure(new AlertDialog.Builder(activity)
                .setTitle(heading)
                .setMessage(details)
                .setPositiveButton(replacement ? "Trust replacement" : "Trust Termux",
                        (dialog, which) -> approve.run())
                .setNegativeButton("Cancel", (dialog, which) -> cancel.run())
                .setOnCancelListener(dialog -> cancel.run()));
    }
}
