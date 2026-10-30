package app.termuxvault.secure;

import android.app.AlertDialog;

import java.util.concurrent.atomic.AtomicBoolean;

/** Shared enrollment copy and failure presentation for setup and Settings. */
final class BiometricEnrollmentUi {
    static final String REQUIREMENT =
            "Termux Vault requires a Class 3 (strong) biometric to protect the vault key. "
                    + "Class 2 biometrics and device credentials are not used for vault unlock.";
    static final String OFFER =
            "Would you like to add optional biometric unlock now?\n\n" + REQUIREMENT;
    static final String ADD_ACTION = "Add Class 3 biometric";
    static final String PROMPT_SUBTITLE =
            "Use your Class 3 biometric to protect the vault key";
    static final String FAQ_CLASS_GUIDANCE =
            "Android classifies biometric implementations by strength. Class 3 (formerly Strong) "
                    + "is the class Android permits to authorize the Keystore cryptographic key "
                    + "used for Vault unlock. Class 2 (formerly Weak) can be suitable for other "
                    + "phone features, but Android does not allow it to authorize this key. Vault "
                    + "therefore cannot enable Class 2 by simply relaxing a setting. Supporting it "
                    + "would require a separate app-level gate and a differently protected vault "
                    + "key, weakening and complicating the security architecture. If only Class 2 "
                    + "is available, the vault remains fully usable with its passphrase. A "
                    + "functional Class 3 key that works but does not confirm every additional "
                    + "requested protection uses a soft warning and can proceed with explicit consent.";

    private BiometricEnrollmentUi() {}

    static BiometricAvailability.Status availabilityFor(
            BiometricEnrollment.Failure failure) {
        return switch (failure) {
            case CLASS_2_ONLY -> BiometricAvailability.Status.CLASS_2_ONLY;
            case STRONG_BIOMETRIC_NOT_ENROLLED -> BiometricAvailability.Status.NOT_ENROLLED;
            case STRONG_BIOMETRIC_TEMPORARY, HARDWARE_TEMPORARY ->
                    BiometricAvailability.Status.TEMPORARILY_UNAVAILABLE;
            case STRONG_BIOMETRIC_SECURITY_UPDATE ->
                    BiometricAvailability.Status.SECURITY_UPDATE_REQUIRED;
            case STRONG_BIOMETRIC_DISABLED -> BiometricAvailability.Status.DISABLED_FOR_APPS;
            case STRONG_BIOMETRIC_NO_HARDWARE -> BiometricAvailability.Status.NO_HARDWARE;
            case STRONG_BIOMETRIC_UNSUPPORTED -> BiometricAvailability.Status.UNSUPPORTED;
            case STRONG_BIOMETRIC_UNAVAILABLE -> BiometricAvailability.Status.UNKNOWN;
            default -> null;
        };
    }

    static boolean showAvailabilityFailure(SecureActivity activity,
                                           BiometricEnrollment.Failure failure,
                                           BiometricAvailability.Callback callback) {
        BiometricAvailability.Status availability = availabilityFor(failure);
        if (availability == null) return false;
        BiometricAvailability.showUnavailable(activity, availability, callback);
        return true;
    }

    static String failureMessage(BiometricEnrollment.Failure failure, String finalGuidance) {
        return "Biometric unlock was not enabled. " + failure.message + "\n\n" + finalGuidance;
    }

    static void showFailure(SecureActivity activity, BiometricEnrollment.Failure failure,
                            String finalGuidance, Runnable onContinue) {
        if (activity.isFinishing() || activity.isDestroyed()) return;
        AtomicBoolean completed = new AtomicBoolean(false);
        Runnable finishOnce = () -> {
            if (completed.compareAndSet(false, true)) onContinue.run();
        };
        Ui.showSecure(new AlertDialog.Builder(activity)
                .setTitle("Biometric unlock not enabled")
                .setMessage(failureMessage(failure, finalGuidance))
                .setPositiveButton("Continue", (dialog, which) -> finishOnce.run())
                .setOnCancelListener(dialog -> finishOnce.run()));
    }
}
