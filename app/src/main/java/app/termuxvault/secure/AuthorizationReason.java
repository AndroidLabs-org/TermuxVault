package app.termuxvault.secure;

/** Builds non-secret, action-specific text shared by biometric and passphrase authorization. */
final class AuthorizationReason {
    private AuthorizationReason() {}

    static String createCommand() {
        return "Create a protected command";
    }

    static String editCommand(String title) {
        return "Edit protected command: " + TextPolicy.safeDisplayTitle(title);
    }

    static String editUnknownCommand() {
        return "Edit a protected command";
    }

    static String runCommand(String title) {
        return "Run protected command: " + TextPolicy.safeDisplayTitle(title);
    }

    static String trustAndRun(String title) {
        return "Trust this Termux identity and run protected command: "
                + TextPolicy.safeDisplayTitle(title);
    }

    static String deleteCommand(String title) {
        return "Delete protected command: " + TextPolicy.safeDisplayTitle(title);
    }

    static String importCommands(int count) {
        if (count == 1) return "Import 1 protected command into this vault";
        return "Import " + Math.max(0, count) + " protected commands into this vault";
    }

    static String trustTermux(boolean replacing) {
        return replacing ? "Replace the trusted Termux identity" : "Trust this Termux identity";
    }

    static String untrustTermux() {
        return "Remove trust from Termux";
    }

    static String enableBiometric() {
        return "Enable biometric unlock for this vault";
    }
}
