package app.termuxvault.secure;

import java.util.HashSet;
import java.util.Set;

/** Process-local guard against dispatching the same entry twice during authentication/handoff. */
final class RunInFlightGuard {
    private static final Set<String> ACTIVE_ENTRY_IDS = new HashSet<>();

    private RunInFlightGuard() {}

    static boolean tryAcquire(String entryId) {
        if (entryId == null) return false;
        synchronized (ACTIVE_ENTRY_IDS) {
            return ACTIVE_ENTRY_IDS.add(entryId);
        }
    }

    static void release(String entryId) {
        if (entryId == null) return;
        synchronized (ACTIVE_ENTRY_IDS) {
            ACTIVE_ENTRY_IDS.remove(entryId);
        }
    }
}
