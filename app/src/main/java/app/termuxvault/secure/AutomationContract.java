package app.termuxvault.secure;

final class AutomationContract {
    static final String ACTION_SUFFIX = ".RUN_ENTRY";
    static final String EXTRA_ENTRY_ID = "entry_id";
    static final String TARGET = "Broadcast Receiver";

    private AutomationContract() {}

    static String action(String packageName) {
        return packageName + ACTION_SUFFIX;
    }

    static String extra(String entryId) {
        return EXTRA_ENTRY_ID + ":" + entryId;
    }

    static String copyAll(String packageName, String entryId) {
        return "Action: " + action(packageName) + "\n"
                + "Package: " + packageName + "\n"
                + "Extra: " + extra(entryId);
    }
}
