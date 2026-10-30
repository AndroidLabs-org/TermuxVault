package app.termuxvault.secure;

/** Shared aggregate result copy for the Termux terminal, FAQ, and completion notification. */
final class RunOutcomeText {
    static final String SUCCESS = "All commands completed successfully";
    static final String FAILURE = "At least one line in this command failed";
    static final String SUCCESS_SENTENCE = SUCCESS + ".";
    static final String FAILURE_SENTENCE = FAILURE + ".";

    private RunOutcomeText() {}
}
