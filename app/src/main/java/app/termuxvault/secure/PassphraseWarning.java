package app.termuxvault.secure;

import android.app.AlertDialog;

import java.util.concurrent.atomic.AtomicBoolean;

/** Non-blocking strength guidance. Vault and backup passphrases remain non-empty-only. */
final class PassphraseWarning {
    static final int MIN_CHARACTERS = 12;

    private static final String GUIDANCE =
            "Use a unique passphrase of 12 or more characters that includes uppercase and "
                    + "lowercase letters, a number, and a symbol. Weaker passphrases are allowed, "
                    + "but provide less protection.";

    private static final String WARNING =
            "This passphrase does not meet the recommended strength policy (12 or more characters "
                    + "with uppercase and lowercase letters, a number, and a symbol) and may be "
                    + "easier to brute-force. Continue anyway?";

    enum Purpose {
        VAULT,
        BACKUP
    }

    interface Callback {
        void onDecision(boolean useAnyway);
    }

    private static final class WarningSession {
        private final SecureActivity activity;
        private final Callback callback;
        private final AtomicBoolean answered = new AtomicBoolean(false);
        private final Runnable foregroundObserver = () -> decide(false, true);
        private AlertDialog dialog;

        WarningSession(SecureActivity activity, Callback callback) {
            this.activity = activity;
            this.callback = callback;
        }

        boolean begin() {
            if (activity.addForegroundLossObserver(foregroundObserver)) return true;
            answered.set(true);
            callback.onDecision(false);
            return false;
        }

        void attach(AlertDialog value) {
            dialog = value;
        }

        void decide(boolean useAnyway, boolean dismiss) {
            if (!answered.compareAndSet(false, true)) return;
            activity.removeForegroundLossObserver(foregroundObserver);
            AlertDialog activeDialog = dialog;
            dialog = null;
            if (dismiss && activeDialog != null && activeDialog.isShowing()) {
                activeDialog.dismiss();
            }
            callback.onDecision(useAnyway);
        }
    }

    private PassphraseWarning() {}

    /** True when a non-empty passphrase should show the optional strength warning. */
    static boolean isTooWeak(char[] passphrase) {
        if (passphrase == null || passphrase.length == 0) return false;
        if (Character.codePointCount(passphrase, 0, passphrase.length) < MIN_CHARACTERS) {
            return true;
        }
        return !meetsCharacterPolicy(passphrase);
    }

    static boolean meetsCharacterPolicy(char[] passphrase) {
        if (passphrase == null || passphrase.length == 0) return false;
        boolean upper = false;
        boolean lower = false;
        boolean digit = false;
        boolean symbol = false;
        for (int index = 0; index < passphrase.length; ) {
            int codePoint = Character.codePointAt(passphrase, index);
            index += Character.charCount(codePoint);
            if (Character.isUpperCase(codePoint)) {
                upper = true;
            } else if (Character.isLowerCase(codePoint)) {
                lower = true;
            } else if (Character.isDigit(codePoint)) {
                digit = true;
            } else if (!Character.isLetter(codePoint)
                    && !Character.isWhitespace(codePoint)
                    && !Character.isISOControl(codePoint)) {
                symbol = true;
            }
        }
        return upper && lower && digit && symbol;
    }

    static String guidance() {
        return GUIDANCE;
    }

    static String title(Purpose purpose) {
        return purpose == Purpose.BACKUP
                ? "Use a stronger backup passphrase?"
                : "Use a stronger vault passphrase?";
    }

    static String message(Purpose purpose) {
        return WARNING;
    }

    static void show(SecureActivity activity, Purpose purpose, Callback callback) {
        WarningSession session = new WarningSession(activity, callback);
        if (!session.begin()) return;
        AlertDialog dialog = Ui.createSecure(new AlertDialog.Builder(activity)
                .setTitle(title(purpose))
                .setMessage(message(purpose))
                .setPositiveButton("Choose a stronger passphrase", (ignored, which) -> {
                    session.decide(false, false);
                })
                .setNegativeButton("Use anyway", (ignored, which) -> {
                    session.decide(true, false);
                })
                .setOnCancelListener(ignored -> session.decide(false, false)));
        session.attach(dialog);
        dialog.setOnDismissListener(ignored -> session.decide(false, false));
        dialog.show();
    }

    static void requireVaultPassphrase(char[] passphrase) throws VaultException {
        if (passphrase == null || passphrase.length == 0) {
            throw new VaultException("Vault passphrase cannot be empty");
        }
    }

    static void requireBackupPassphrase(char[] passphrase) throws VaultException {
        if (passphrase == null || passphrase.length == 0) {
            throw new VaultException("Backup passphrase cannot be empty");
        }
    }
}
