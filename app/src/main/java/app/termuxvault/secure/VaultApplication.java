package app.termuxvault.secure;

import android.app.Activity;
import android.app.Application;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

public final class VaultApplication extends Application {
    private static final long FOREGROUND_LOSS_CONFIRMATION_MS = 100L;
    static final String AUTOMATION_CHANNEL = "protected-command-requests";
    static final String COMPLETION_CHANNEL = "protected-command-completions";

    private final AppForegroundTracker<Activity> foregroundTracker =
            new AppForegroundTracker<>();
    private final Set<SecureActivity> secureActivities =
            Collections.newSetFromMap(new IdentityHashMap<>());
    private Handler mainHandler;

    @Override
    public void onCreate() {
        super.onCreate();
        mainHandler = new Handler(Looper.getMainLooper());
        registerActivityLifecycleCallbacks(new ForegroundCallbacks());
        NotificationChannel channel = new NotificationChannel(
                AUTOMATION_CHANNEL,
                "Protected command requests",
                NotificationManager.IMPORTANCE_HIGH);
        channel.setDescription("Authentication requests initiated by Tasker");
        channel.setShowBadge(true);
        getSystemService(NotificationManager.class).createNotificationChannel(channel);

        NotificationChannel completions = new NotificationChannel(
                COMPLETION_CHANNEL,
                "Protected command completions",
                NotificationManager.IMPORTANCE_DEFAULT);
        completions.setDescription("Optional completion status for protected commands");
        completions.setShowBadge(true);
        getSystemService(NotificationManager.class).createNotificationChannel(completions);
        CompletionStore.pruneInvalid(this);
    }

    private void scheduleForegroundLoss(long token) {
        if (token == AppForegroundTracker.NO_PENDING_LOSS) return;
        // A launch within this process normally starts the next Activity before the old one stops.
        // Confirming on the next main-loop turn also covers vendor lifecycle ordering that briefly
        // reports zero started Activities during an internal transition.
        mainHandler.postDelayed(() -> {
            if (!foregroundTracker.confirmLoss(token)) return;
            for (SecureActivity activity : new ArrayList<>(secureActivities)) {
                activity.applicationForegroundLost();
            }
        }, FOREGROUND_LOSS_CONFIRMATION_MS);
    }

    private final class ForegroundCallbacks implements ActivityLifecycleCallbacks {
        @Override
        public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
            if (activity instanceof SecureActivity secureActivity) {
                secureActivities.add(secureActivity);
            }
        }

        @Override
        public void onActivityStarted(Activity activity) {
            if (!(activity instanceof SecureActivity)) return;
            if (foregroundTracker.started(activity)) {
                for (SecureActivity secureActivity : new ArrayList<>(secureActivities)) {
                    secureActivity.applicationForegroundGained();
                }
            }
        }

        @Override
        public void onActivityResumed(Activity activity) {}

        @Override
        public void onActivityPaused(Activity activity) {}

        @Override
        public void onActivityStopped(Activity activity) {
            if (activity instanceof SecureActivity) {
                scheduleForegroundLoss(foregroundTracker.stopped(activity));
            }
        }

        @Override
        public void onActivitySaveInstanceState(Activity activity, Bundle outState) {}

        @Override
        public void onActivityDestroyed(Activity activity) {
            if (activity instanceof SecureActivity secureActivity) {
                secureActivities.remove(secureActivity);
                scheduleForegroundLoss(foregroundTracker.stopped(activity));
            }
        }
    }
}
