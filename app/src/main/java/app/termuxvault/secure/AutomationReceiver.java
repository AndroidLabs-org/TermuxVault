package app.termuxvault.secure;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.SystemClock;
import android.net.Uri;

import java.util.Map;

public final class AutomationReceiver extends BroadcastReceiver {
    private static final String THROTTLE_PREFERENCES = "automation-throttle";
    private static final String THROTTLE_KEY_PREFIX = "entry:";
    private static final long MIN_INTERVAL_MS = 3_000;
    private static final PerEntryThrottle THROTTLE =
            new PerEntryThrottle(THROTTLE_KEY_PREFIX, MIN_INTERVAL_MS);

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;
        String id;
        try {
            if (!AutomationContract.action(context.getPackageName()).equals(intent.getAction())) return;
            id = AutomationRequest.canonicalEntryId(
                    intent.getStringExtra(AutomationContract.EXTRA_ENTRY_ID));
        } catch (RuntimeException exception) {
            // Exported receivers must treat malformed or wrong-type extras as untrusted input.
            return;
        }
        if (id == null) return;
        if (android.os.Build.VERSION.SDK_INT >= 33
                && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) return;

        VaultState.Entry entry;
        try {
            entry = new VaultStore(context).load().findEntry(id);
        } catch (VaultException | RuntimeException exception) {
            return;
        }
        if (entry == null) return;

        try {
            SharedPreferences preferences = context.getSharedPreferences(
                    THROTTLE_PREFERENCES, Context.MODE_PRIVATE);
            long now = SystemClock.elapsedRealtime();
            if (!THROTTLE.tryAcquire(new PerEntryThrottle.Store() {
                @Override
                public Map<String, ?> read() {
                    return preferences.getAll();
                }

                @Override
                public void replace(Map<String, Long> markers) {
                    SharedPreferences.Editor editor = preferences.edit().clear();
                    for (Map.Entry<String, Long> marker : markers.entrySet()) {
                        editor.putLong(marker.getKey(), marker.getValue());
                    }
                    editor.apply();
                }
            }, id, now)) return;
        } catch (RuntimeException exception) {
            // Corrupt or unavailable preference state must fail closed without crashing Tasker.
            return;
        }

        try {
            Intent run = RunEntryActivity.createIntent(context, id)
                    .setData(new Uri.Builder().scheme("termuxvault").authority("run")
                            .appendPath(id).build())
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            PendingIntent pending = PendingIntent.getActivity(context, id.hashCode(), run,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            Notification publicVersion = new Notification.Builder(
                    context, VaultApplication.AUTOMATION_CHANNEL)
                    .setSmallIcon(app.termuxvault.secure.R.drawable.ic_stat_vault)
                    .setContentTitle("Termux Vault")
                    .setContentText("Authentication required")
                    .build();
            Notification notification = new Notification.Builder(
                    context, VaultApplication.AUTOMATION_CHANNEL)
                    .setSmallIcon(app.termuxvault.secure.R.drawable.ic_stat_vault)
                    .setContentTitle(TextPolicy.safeDisplayTitle(entry.title))
                    .setContentText("Tap to authenticate and run")
                    .setCategory(Notification.CATEGORY_EVENT)
                    .setVisibility(Notification.VISIBILITY_SECRET)
                    .setPublicVersion(publicVersion)
                    .setContentIntent(pending)
                    .setAutoCancel(true)
                    .build();
            NotificationManager notifications = context.getSystemService(NotificationManager.class);
            notifications.notify(NotificationIdentity.automationTag(id),
                    NotificationIdentity.TAGGED_NOTIFICATION_ID, notification);
            // One-release migration: remove the pre-1.0.14 untagged notification identity.
            notifications.cancel(NotificationIdentity.legacyNumericId(id));
        } catch (RuntimeException ignored) {
            // Notification access can change while an exported broadcast is being handled.
        }
    }

    @SuppressLint("ApplySharedPref") // Vault reset must durably remove the throttle marker.
    static void clearThrottle(Context context) throws VaultException {
        try {
            SharedPreferences preferences = context.getSharedPreferences(
                    THROTTLE_PREFERENCES, Context.MODE_PRIVATE);
            THROTTLE.clear(new PerEntryThrottle.Store() {
                @Override
                public Map<String, ?> read() {
                    return preferences.getAll();
                }

                @Override
                public void replace(Map<String, Long> markers) {
                    if (!preferences.edit().clear().commit()) {
                        throw new IllegalStateException("Automation state could not be cleared");
                    }
                }
            });
        } catch (RuntimeException exception) {
            throw new VaultException("Automation state could not be cleared", exception);
        }
    }
}
