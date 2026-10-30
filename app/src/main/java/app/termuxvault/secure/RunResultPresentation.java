package app.termuxvault.secure;

/**
 * Android-free state for presenting the fixed, non-sensitive result of a Termux handoff.
 *
 * <p>The handoff may finish while Termux owns the foreground. In that case the result is retained
 * only in this Activity instance and consumed once when the Activity resumes. Nothing is persisted
 * across process death.</p>
 */
final class RunResultPresentation {
    static final class Failure {
        final String message;
        final boolean offerTermuxAppInfo;

        Failure(String message, boolean offerTermuxAppInfo) {
            this.message = message;
            this.offerTermuxAppInfo = offerTermuxAppInfo;
        }
    }

    private boolean resumed;
    private Failure pendingFailure;

    Failure resume() {
        resumed = true;
        Failure result = pendingFailure;
        pendingFailure = null;
        return result;
    }

    void pause() {
        resumed = false;
    }

    Failure failed(String message, boolean offerTermuxAppInfo) {
        Failure failure = new Failure(message, offerTermuxAppInfo);
        if (resumed) return failure;
        pendingFailure = failure;
        return null;
    }

    boolean hasPendingFailure() {
        return pendingFailure != null;
    }

    void clear() {
        pendingFailure = null;
    }
}
