package app.termuxvault.secure;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;

public final class CompletionReceiver extends BroadcastReceiver {
    static final String ACTION_SUFFIX = ".COMMAND_FINISHED";
    static final String EXTRA_RUN_ID = "run_id";
    static final String EXTRA_TOKEN = "token";
    static final String EXTRA_STATUS = "status";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;
        String id;
        String token;
        int status;
        try {
            if (!(context.getPackageName() + ACTION_SUFFIX).equals(intent.getAction())) return;
            id = intent.getStringExtra(EXTRA_RUN_ID);
            token = intent.getStringExtra(EXTRA_TOKEN);
            if (!intent.hasExtra(EXTRA_STATUS)) return;
            status = intent.getIntExtra(EXTRA_STATUS, -1);
        } catch (RuntimeException exception) {
            // An exported receiver must treat malformed extras as an unauthenticated request.
            return;
        }
        // Reject malformed exported broadcasts before touching the vault or hashing the installed
        // Termux certificate. This keeps unauthenticated work small and predictably bounded.
        if (!CompletionAuth.isLowerHex(id, CompletionAuth.RUN_ID_BYTES)
                || !CompletionAuth.isLowerHex(token, CompletionAuth.TOKEN_BYTES)
                || status < 0 || status > 255) return;

        // Android 14 sender identity is opt-in and Termux's am broadcast path does not share it.
        // The live sender authorization is therefore the one-time 256-bit token, which Vault sent
        // only to Termux's explicit service. This separate check rejects a replaced Termux install.
        if (!trustedTermuxInstallation(context)) return;

        // Keep the authenticated one-time request available if Android cannot currently post the
        // requested notification. A later legitimate retry can still consume it.
        if (!NotificationAccess.canPostCompletion(context)) return;
        CompletionStore.Record record = CompletionStore.verifyAndConsume(context, id, token);
        if (record == null) return;
        try {
            postNotification(context, record.title, id, status);
        } catch (RuntimeException ignored) {
            // Notification state can change between the availability check and notify(). The
            // authenticated token has already been consumed, but the receiver process must not
            // crash if Android revokes access or rejects the notification during that race.
        }
    }

    private boolean trustedTermuxInstallation(Context context) {
        try {
            VaultState state = new VaultStore(context).load();
            return TermuxIdentity.read(context).matches(state.trustedTermuxCertificates);
        } catch (PackageManager.NameNotFoundException | VaultException | RuntimeException exception) {
            return false;
        }
    }

    private static void postNotification(Context context, String title, String id, int status) {
        Intent openTermux = new Intent(Intent.ACTION_MAIN)
                .setComponent(new ComponentName(TermuxIdentity.PACKAGE_NAME, TermuxIdentity.ACTIVITY_NAME))
                .addCategory(Intent.CATEGORY_LAUNCHER)
                .setData(new Uri.Builder().scheme("termuxvault-complete").authority(id).build())
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        PendingIntent pending = PendingIntent.getActivity(context, id.hashCode(), openTermux,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification publicVersion = new Notification.Builder(
                context, VaultApplication.COMPLETION_CHANNEL)
                .setSmallIcon(R.drawable.ic_stat_vault)
                .setContentTitle("Termux Vault")
                .setContentText("A protected command finished")
                .build();
        String detail = detailForStatus(status);
        Notification notification = new Notification.Builder(
                context, VaultApplication.COMPLETION_CHANNEL)
                .setSmallIcon(R.drawable.ic_stat_vault)
                .setContentTitle(TextPolicy.safeDisplayTitle(title))
                .setContentText(detail)
                .setCategory(Notification.CATEGORY_STATUS)
                .setVisibility(Notification.VISIBILITY_SECRET)
                .setPublicVersion(publicVersion)
                .setContentIntent(pending)
                .setAutoCancel(true)
                .setOnlyAlertOnce(true)
                .build();
        NotificationManager notifications = context.getSystemService(NotificationManager.class);
        notifications.notify(NotificationIdentity.completionTag(id),
                NotificationIdentity.TAGGED_NOTIFICATION_ID, notification);
        // One-release migration: remove the pre-1.0.14 untagged notification identity.
        notifications.cancel(NotificationIdentity.legacyNumericId(id));
    }

    static String detailForStatus(int status) {
        return (status == 0 ? RunOutcomeText.SUCCESS : RunOutcomeText.FAILURE)
                + " — tap to open Termux";
    }
}
