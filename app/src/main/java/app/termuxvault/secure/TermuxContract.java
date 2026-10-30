package app.termuxvault.secure;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;

final class TermuxContract {
    enum Status {
        ALLOWED(true, "Allowed"),
        PERMISSION_REQUIRED(false, "Permission required"),
        TERMUX_NOT_INSTALLED(false, "Termux not installed"),
        UNAVAILABLE(false, "Unavailable");

        final boolean available;
        final String label;

        Status(boolean available, String label) {
            this.available = available;
            this.label = label;
        }
    }

    static final String RUN_PERMISSION = "com.termux.permission.RUN_COMMAND";
    static final String ACTION_RUN_COMMAND = "com.termux.RUN_COMMAND";
    static final String EXTRA_PATH = "com.termux.RUN_COMMAND_PATH";
    static final String EXTRA_ARGUMENTS = "com.termux.RUN_COMMAND_ARGUMENTS";
    static final String EXTRA_BACKGROUND = "com.termux.RUN_COMMAND_BACKGROUND";
    static final String EXTRA_BACKGROUND_CUSTOM_LOG_LEVEL =
            "com.termux.RUN_COMMAND_BACKGROUND_CUSTOM_LOG_LEVEL";
    static final String EXTRA_SESSION_ACTION = "com.termux.RUN_COMMAND_SESSION_ACTION";
    static final String SESSION_ACTION_SWITCH_TO_NEW_DONT_OPEN = "2";
    static final int PERMISSION_REQUEST_CODE = 2401;
    private static final String PERMISSION_PREFERENCES = "android-permission-requests";
    private static final String RUN_PERMISSION_REQUESTED = "termux-run-command-requested";

    private TermuxContract() {}

    static boolean hasRunPermission(Context context) {
        return context.checkSelfPermission(RUN_PERMISSION) == PackageManager.PERMISSION_GRANTED;
    }

    static Status status(Context context) {
        try {
            context.getPackageManager().getPackageInfo(TermuxIdentity.PACKAGE_NAME, 0);
            return hasRunPermission(context) ? Status.ALLOWED : Status.PERMISSION_REQUIRED;
        } catch (PackageManager.NameNotFoundException exception) {
            return Status.TERMUX_NOT_INSTALLED;
        } catch (RuntimeException exception) {
            return Status.UNAVAILABLE;
        }
    }

    static boolean wasRunPermissionRequested(Context context) {
        return preferences(context).getBoolean(RUN_PERMISSION_REQUESTED, false);
    }

    static void markRunPermissionRequested(Context context) {
        preferences(context).edit().putBoolean(RUN_PERMISSION_REQUESTED, true).apply();
    }

    static boolean shouldShowRunPermissionRationale(Activity activity) {
        return activity.shouldShowRequestPermissionRationale(RUN_PERMISSION);
    }

    static void requestRunPermission(Activity activity) {
        markRunPermissionRequested(activity);
        activity.requestPermissions(new String[]{RUN_PERMISSION}, PERMISSION_REQUEST_CODE);
    }

    @SuppressLint("ApplySharedPref") // Vault reset must durably remove the request-history marker.
    static void clearRequestHistory(Context context) throws VaultException {
        try {
            if (!preferences(context).edit().clear().commit()) {
                throw new VaultException("Android permission request history could not be cleared");
            }
        } catch (VaultException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new VaultException(
                    "Android permission request history could not be cleared", exception);
        }
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(PERMISSION_PREFERENCES, Context.MODE_PRIVATE);
    }
}
