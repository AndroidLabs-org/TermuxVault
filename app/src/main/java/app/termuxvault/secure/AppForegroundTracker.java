package app.termuxvault.secure;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

/**
 * Small, Android-free state machine used by {@link VaultApplication}.
 *
 * <p>A token is returned when the last tracked Activity stops. The caller confirms that token
 * on the next main-loop turn. Starting another Activity in the meantime invalidates the token,
 * which prevents an in-app Activity transition from being mistaken for backgrounding the app.</p>
 */
final class AppForegroundTracker<T> {
    static final long NO_PENDING_LOSS = -1L;

    private final Set<T> started = Collections.newSetFromMap(new IdentityHashMap<>());
    private long epoch;
    private boolean lossDelivered = true;

    boolean started(T activity) {
        if (!started.add(activity)) return false;
        if (started.size() == 1) {
            epoch++;
            lossDelivered = false;
            return true;
        }
        return false;
    }

    long stopped(T activity) {
        if (!started.remove(activity) || !started.isEmpty() || lossDelivered) {
            return NO_PENDING_LOSS;
        }
        return epoch;
    }

    boolean confirmLoss(long candidateEpoch) {
        if (candidateEpoch == NO_PENDING_LOSS || candidateEpoch != epoch
                || !started.isEmpty() || lossDelivered) {
            return false;
        }
        lossDelivered = true;
        return true;
    }
}
