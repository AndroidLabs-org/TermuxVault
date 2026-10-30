package app.termuxvault.secure;

import android.Manifest;
import android.app.Activity;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;

final class NotificationAccess {
    enum Status {
        AVAILABLE(true, "Allowed"),
        RUNTIME_PERMISSION_DENIED(false, "Permission required"),
        APP_NOTIFICATIONS_DISABLED(false, "Disabled in Android"),
        CHANNEL_MISSING(false, "Channel unavailable"),
        CHANNEL_DISABLED(false, "Channel disabled"),
        UNAVAILABLE(false, "Unavailable");

        final boolean available;
        final String label;

        Status(boolean available, String label) {
            this.available = available;
            this.label = label;
        }
    }

    private NotificationAccess() {}

    static boolean canPostCompletion(Context context) {
        return status(context, VaultApplication.COMPLETION_CHANNEL).available;
    }

    static Status status(Context context) {
        return status(context, VaultApplication.COMPLETION_CHANNEL);
    }

    static Status status(Context context, String channelId) {
        try {
            boolean runtimePermissionGranted = Build.VERSION.SDK_INT < 33
                    || context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                    == PackageManager.PERMISSION_GRANTED;
            NotificationManager manager = context.getSystemService(NotificationManager.class);
            if (manager == null) return Status.UNAVAILABLE;
            boolean appNotificationsEnabled = manager.areNotificationsEnabled();
            NotificationChannel channel = manager.getNotificationChannel(channelId);
            Integer channelImportance = channel == null ? null : channel.getImportance();
            return evaluate(runtimePermissionGranted, appNotificationsEnabled, channelImportance);
        } catch (RuntimeException exception) {
            return Status.UNAVAILABLE;
        }
    }

    static boolean shouldOfferChannelSettings(Status status) {
        return status == Status.CHANNEL_DISABLED;
    }

    static boolean shouldOfferCompletionChannelSettings(Status status) {
        return shouldOfferChannelSettings(status);
    }

    static void openAppDetails(Context context) {
        Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                .setData(Uri.fromParts("package", context.getPackageName(), null));
        addNewTaskFlagIfNeeded(context, intent);
        try {
            context.startActivity(intent);
        } catch (RuntimeException firstFailure) {
            Intent fallback = new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                    .putExtra(Settings.EXTRA_APP_PACKAGE, context.getPackageName());
            addNewTaskFlagIfNeeded(context, fallback);
            try {
                context.startActivity(fallback);
            } catch (RuntimeException ignored) {
                // The Settings UI is unavailable on this device; keep this action non-fatal.
            }
        }
    }

    static void openCompletionChannelSettings(Context context) {
        openChannelSettings(context, VaultApplication.COMPLETION_CHANNEL);
    }

    static void openAutomationChannelSettings(Context context) {
        openChannelSettings(context, VaultApplication.AUTOMATION_CHANNEL);
    }

    private static void openChannelSettings(Context context, String channelId) {
        Intent intent = new Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, context.getPackageName())
                .putExtra(Settings.EXTRA_CHANNEL_ID, channelId);
        addNewTaskFlagIfNeeded(context, intent);
        try {
            context.startActivity(intent);
        } catch (RuntimeException firstFailure) {
            openAppDetails(context);
        }
    }

    static void openTermuxAppDetails(Context context) {
        Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                .setData(Uri.fromParts("package", TermuxIdentity.PACKAGE_NAME, null));
        addNewTaskFlagIfNeeded(context, intent);
        try {
            context.startActivity(intent);
        } catch (RuntimeException ignored) {
            // The Settings UI is unavailable on this device; keep this action non-fatal.
        }
    }

    private static void addNewTaskFlagIfNeeded(Context context, Intent intent) {
        if (!(context instanceof Activity)) intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    }

    static Status evaluate(boolean runtimePermissionGranted, boolean appNotificationsEnabled,
                           Integer channelImportance) {
        if (!runtimePermissionGranted) return Status.RUNTIME_PERMISSION_DENIED;
        if (!appNotificationsEnabled) return Status.APP_NOTIFICATIONS_DISABLED;
        if (channelImportance == null) return Status.CHANNEL_MISSING;
        if (channelImportance == NotificationManager.IMPORTANCE_NONE) {
            return Status.CHANNEL_DISABLED;
        }
        if (channelImportance < NotificationManager.IMPORTANCE_NONE) return Status.UNAVAILABLE;
        return Status.AVAILABLE;
    }
}
