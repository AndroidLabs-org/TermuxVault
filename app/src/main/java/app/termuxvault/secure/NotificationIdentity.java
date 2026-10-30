package app.termuxvault.secure;

/** Collision-resistant notification identities plus the pre-1.0.14 migration identity. */
final class NotificationIdentity {
    static final int TAGGED_NOTIFICATION_ID = 0;
    private static final String AUTOMATION_PREFIX = "tasker:";
    private static final String COMPLETION_PREFIX = "completion:";

    private NotificationIdentity() {}

    static String automationTag(String entryId) {
        return AUTOMATION_PREFIX + entryId;
    }

    static String completionTag(String runId) {
        return COMPLETION_PREFIX + runId;
    }

    static int legacyNumericId(String stableId) {
        return stableId.hashCode();
    }
}
