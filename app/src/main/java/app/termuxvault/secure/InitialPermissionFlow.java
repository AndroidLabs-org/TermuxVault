package app.termuxvault.secure;

/** Selects the next first-run permission or onboarding step without owning Android UI state. */
final class InitialPermissionFlow {
    enum Step {
        WAIT,
        REQUEST_NOTIFICATIONS,
        REQUEST_TERMUX,
        OFFER_SETUP_GUIDE,
        COMPLETE
    }

    private InitialPermissionFlow() {}

    static Step next(boolean setupGuidePending,
                     boolean requestInFlight,
                     boolean notificationRequestNeeded,
                     boolean termuxRequestNeeded) {
        if (requestInFlight) return Step.WAIT;
        if (notificationRequestNeeded) return Step.REQUEST_NOTIFICATIONS;
        if (termuxRequestNeeded) return Step.REQUEST_TERMUX;
        return setupGuidePending ? Step.OFFER_SETUP_GUIDE : Step.COMPLETE;
    }
}
