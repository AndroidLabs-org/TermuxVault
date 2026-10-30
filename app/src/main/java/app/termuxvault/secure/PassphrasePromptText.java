package app.termuxvault.secure;

/** Android-free copy model so every route keeps the exact authorization context testable. */
final class PassphrasePromptText {
    enum Route {
        DIRECT,
        BIOMETRIC_CHOSEN,
        BIOMETRIC_FAILED,
        BIOMETRIC_INVALIDATED,
        BIOMETRIC_UNAVAILABLE
    }

    private PassphrasePromptText() {}

    static String actionReason(String suppliedReason) {
        if (suppliedReason == null || TextPolicy.isBlank(suppliedReason)) {
            return "Protected vault operation";
        }
        return suppliedReason;
    }

    static String explanation(Route route) {
        return switch (route) {
            case DIRECT -> "Enter the vault passphrase to authorize this action.";
            case BIOMETRIC_CHOSEN -> "You chose to authorize with the vault passphrase. "
                    + "Enter it to continue.";
            case BIOMETRIC_FAILED -> "Biometric authorization did not complete. Enter the vault "
                    + "passphrase to continue; you can try biometric unlock again next time.";
            case BIOMETRIC_INVALIDATED -> "Android invalidated biometric unlock, usually because "
                    + "enrolled biometrics changed. Enter the vault passphrase to continue. Open "
                    + "Settings and use Reset biometric unlock to remove the obsolete material; "
                    + "you can add biometric unlock again later.";
            case BIOMETRIC_UNAVAILABLE -> "Biometric unlock is no longer available. Enter the "
                    + "vault passphrase to continue. Open Settings and use Reset biometric unlock "
                    + "to remove the unusable material; you can add biometric unlock again later.";
        };
    }
}
