package app.termuxvault.secure;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;

/** Durable, non-secret state for the one-time Termux setup-guide offer. */
final class TermuxSetupOnboarding {
    interface Store {
        int read();

        boolean write(int state);
    }

    private static final String PREFERENCES = "termux-setup-onboarding";
    private static final String STATE_KEY = "setup-guide-offer-state";
    private static final int ABSENT = 0;
    private static final int PENDING = 1;
    private static final int COMPLETE = 2;
    private static final Object LOCK = new Object();

    private TermuxSetupOnboarding() {}

    static boolean isPending(Context context) {
        try {
            return isPending(preferencesStore(context));
        } catch (RuntimeException ignored) {
            // Onboarding must never prevent an existing vault from opening.
            return false;
        }
    }

    static boolean markPending(Context context) {
        try {
            return markPending(preferencesStore(context));
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    static boolean markComplete(Context context) {
        try {
            return markComplete(preferencesStore(context));
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    static boolean isPending(Store store) {
        if (store == null) return false;
        synchronized (LOCK) {
            return normalize(store.read()) == PENDING;
        }
    }

    static boolean markPending(Store store) {
        return write(store, PENDING);
    }

    static boolean markComplete(Store store) {
        return write(store, COMPLETE);
    }

    private static boolean write(Store store, int state) {
        if (store == null) return false;
        synchronized (LOCK) {
            return store.write(state);
        }
    }

    private static int normalize(int state) {
        return state == PENDING || state == COMPLETE ? state : ABSENT;
    }

    private static Store preferencesStore(Context context) {
        SharedPreferences preferences = context.getApplicationContext().getSharedPreferences(
                PREFERENCES, Context.MODE_PRIVATE);
        return new Store() {
            @Override
            public int read() {
                return preferences.getInt(STATE_KEY, ABSENT);
            }

            @Override
            @SuppressLint("ApplySharedPref")
            public boolean write(int state) {
                // This marker closes a process-death gap, so the write must complete before the
                // initial vault save or before acting on the user's answer.
                return preferences.edit().putInt(STATE_KEY, state).commit();
            }
        };
    }
}
