package app.termuxvault.secure;

import android.app.AlertDialog;
import android.content.Intent;
import android.hardware.biometrics.BiometricManager;
import android.provider.Settings;

/** Strong-biometric availability classification and reusable, non-alarming recovery UI. */
final class BiometricAvailability {
    // The platform service can return this documented result even though some SDK stubs omit it.
    private static final int RESULT_UNSUPPORTED = -2;

    enum Status {
        STRONG_AVAILABLE,
        CLASS_2_ONLY,
        NOT_ENROLLED,
        TEMPORARILY_UNAVAILABLE,
        SECURITY_UPDATE_REQUIRED,
        DISABLED_FOR_APPS,
        NO_HARDWARE,
        UNSUPPORTED,
        UNKNOWN
    }

    interface Callback {
        void onContinueWithPassphrase();

        void onOpenBiometricSettings();
    }

    private BiometricAvailability() {}

    static Status status(SecureActivity activity) {
        BiometricManager manager = activity.getSystemService(BiometricManager.class);
        if (manager == null) return Status.NO_HARDWARE;
        int strong;
        int weak;
        try {
            strong = manager.canAuthenticate(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG);
            if (strong == BiometricManager.BIOMETRIC_SUCCESS) return Status.STRONG_AVAILABLE;
            weak = manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK);
        } catch (RuntimeException ignored) {
            return Status.UNKNOWN;
        }
        return classify(strong, weak);
    }

    static Status classify(int strongResult, int weakResult) {
        if (strongResult == BiometricManager.BIOMETRIC_SUCCESS) return Status.STRONG_AVAILABLE;
        if (weakResult == BiometricManager.BIOMETRIC_SUCCESS) return Status.CLASS_2_ONLY;
        if (strongResult == BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE) {
            return Status.TEMPORARILY_UNAVAILABLE;
        }
        if (strongResult == BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED) {
            return Status.SECURITY_UPDATE_REQUIRED;
        }
        if (strongResult == BiometricManager.BIOMETRIC_ERROR_NOT_ENABLED_FOR_APPS) {
            return Status.DISABLED_FOR_APPS;
        }
        if (strongResult == BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE) {
            return Status.NO_HARDWARE;
        }
        if (strongResult == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED) {
            return Status.NOT_ENROLLED;
        }
        if (strongResult == RESULT_UNSUPPORTED) return Status.UNSUPPORTED;
        return Status.UNKNOWN;
    }

    static String title(Status status) {
        return switch (status) {
            case CLASS_2_ONLY -> "Class 3 biometric required";
            case NOT_ENROLLED -> "Set up a Class 3 biometric";
            case TEMPORARILY_UNAVAILABLE -> "Biometric sensor temporarily unavailable";
            case SECURITY_UPDATE_REQUIRED -> "Android security update required";
            case DISABLED_FOR_APPS -> "Biometrics disabled for apps";
            case NO_HARDWARE -> "No compatible biometric hardware";
            case UNSUPPORTED -> "Biometric unlock unavailable";
            case UNKNOWN -> "Biometric status unavailable";
            case STRONG_AVAILABLE -> "Class 3 biometric available";
        };
    }

    static String message(Status status) {
        return switch (status) {
            case CLASS_2_ONLY -> "Android reports that this device currently has only a Class 2 "
                    + "biometric available. Android does not allow Class 2 biometrics to authorize "
                    + "the cryptographic key used by Termux Vault, so biometric unlock cannot be "
                    + "enabled with this device configuration.\n\nThis does not mean the biometric "
                    + "is unsafe for every purpose. Your vault remains fully available with its "
                    + "passphrase.";
            case NOT_ENROLLED -> "Android does not report an enrolled Class 3 biometric. Set one "
                    + "up in Android to use biometric unlock. Your vault remains fully available "
                    + "with its passphrase.";
            case TEMPORARILY_UNAVAILABLE -> "Android reports that the biometric sensor is "
                    + "temporarily unavailable. Try again later. Your vault remains fully "
                    + "available with its passphrase.";
            case SECURITY_UPDATE_REQUIRED -> "Android requires a security update before this "
                    + "biometric can authorize cryptographic keys. Your vault remains fully "
                    + "available with its passphrase.";
            case DISABLED_FOR_APPS -> "Android currently prevents apps from using biometrics. "
                    + "Review the device's biometric settings, or continue using the vault "
                    + "passphrase.";
            case NO_HARDWARE -> "Android reports no biometric hardware capable of authorizing "
                    + "the cryptographic key used by Termux Vault. The vault remains fully "
                    + "available with its passphrase.";
            case UNSUPPORTED -> "Android does not support the strong cryptographic biometric "
                    + "operation required by Termux Vault. The vault remains fully available "
                    + "with its passphrase.";
            case UNKNOWN -> "Android could not confirm that a Class 3 biometric is currently "
                    + "available. The vault remains fully available with its passphrase.";
            case STRONG_AVAILABLE -> "Android reports an available Class 3 biometric.";
        };
    }

    static boolean canOpenSettings(Status status) {
        return status == Status.CLASS_2_ONLY || status == Status.NOT_ENROLLED
                || status == Status.DISABLED_FOR_APPS || status == Status.UNKNOWN;
    }

    static void showUnavailable(SecureActivity activity, Status status, Callback callback) {
        if (status == Status.STRONG_AVAILABLE) return;
        AlertDialog.Builder builder = new AlertDialog.Builder(activity)
                .setTitle(title(status))
                .setMessage(message(status))
                .setOnCancelListener(dialog -> callback.onContinueWithPassphrase());
        if (canOpenSettings(status)) {
            builder.setPositiveButton("Open biometric settings",
                            (dialog, which) -> callback.onOpenBiometricSettings())
                    .setNegativeButton("Continue with passphrase",
                            (dialog, which) -> callback.onContinueWithPassphrase());
        } else {
            builder.setPositiveButton("Continue with passphrase",
                    (dialog, which) -> callback.onContinueWithPassphrase());
        }
        Ui.showSecure(builder);
    }

    static boolean openSettings(SecureActivity activity) {
        Intent enrollment = new Intent(Settings.ACTION_BIOMETRIC_ENROLL)
                .putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                        BiometricManager.Authenticators.BIOMETRIC_STRONG);
        if (startResolvable(activity, enrollment)) return true;
        return startResolvable(activity, new Intent(Settings.ACTION_SECURITY_SETTINGS));
    }

    private static boolean startResolvable(SecureActivity activity, Intent intent) {
        try {
            if (intent.resolveActivity(activity.getPackageManager()) == null) return false;
            activity.startActivity(intent);
            return true;
        } catch (RuntimeException ignored) {
            return false;
        }
    }
}
