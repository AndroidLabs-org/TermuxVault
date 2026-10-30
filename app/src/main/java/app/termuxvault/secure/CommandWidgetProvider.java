package app.termuxvault.secure;

import android.annotation.SuppressLint;
import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.util.ArrayMap;
import android.util.SizeF;
import android.util.TypedValue;
import android.widget.RemoteViews;

import java.util.ArrayList;
import java.util.Map;
import java.util.UUID;

public final class CommandWidgetProvider extends AppWidgetProvider {
    private static final String PREFERENCES = "command-widgets";
    private static final String BINDING_CHOOSE_EACH_TIME = "mode:choose-each-time";
    private static final String BINDING_ENTRY_PREFIX = "entry:";

    @Override
    public void onUpdate(Context context, AppWidgetManager manager, int[] appWidgetIds) {
        for (int widgetId : appWidgetIds) updateWidget(context, manager, widgetId);
    }

    @Override
    public void onAppWidgetOptionsChanged(Context context, AppWidgetManager manager,
                                          int appWidgetId, Bundle newOptions) {
        super.onAppWidgetOptionsChanged(context, manager, appWidgetId, newOptions);
        updateWidget(context, manager, appWidgetId);
    }

    @Override
    public void onDeleted(Context context, int[] appWidgetIds) {
        SharedPreferences.Editor editor = preferences(context).edit();
        for (int widgetId : appWidgetIds) editor.remove(Integer.toString(widgetId));
        editor.apply();
    }

    static void assign(Context context, int widgetId, String entryId) {
        String binding = encodeEntryBinding(entryId);
        if (binding == null) binding = BINDING_CHOOSE_EACH_TIME;
        preferences(context).edit().putString(Integer.toString(widgetId), binding).apply();
        updateWidget(context, AppWidgetManager.getInstance(context), widgetId);
    }

    static void assignChooseEachTime(Context context, int widgetId) {
        preferences(context).edit()
                .putString(Integer.toString(widgetId), BINDING_CHOOSE_EACH_TIME)
                .apply();
        updateWidget(context, AppWidgetManager.getInstance(context), widgetId);
    }

    static void refreshAll(Context context) {
        AppWidgetManager manager = AppWidgetManager.getInstance(context);
        int[] ids = manager.getAppWidgetIds(new ComponentName(context, CommandWidgetProvider.class));
        for (int id : ids) updateWidget(context, manager, id);
    }

    @SuppressLint("ApplySharedPref") // A destructive vault operation must durably sever bindings.
    static void resetAllToChoose(Context context) throws VaultException {
        try {
            AppWidgetManager manager = AppWidgetManager.getInstance(context);
            int[] ids = manager.getAppWidgetIds(
                    new ComponentName(context, CommandWidgetProvider.class));
            SharedPreferences.Editor editor = preferences(context).edit().clear();
            for (int id : ids) {
                editor.putString(Integer.toString(id), BINDING_CHOOSE_EACH_TIME);
            }
            if (!editor.commit()) {
                throw new VaultException("Widget bindings could not be cleared");
            }
            for (int id : ids) updateWidget(context, manager, id);
        } catch (VaultException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new VaultException("Widget bindings could not be cleared", exception);
        }
    }

    private static void updateWidget(Context context, AppWidgetManager manager, int widgetId) {
        String preferenceKey = Integer.toString(widgetId);
        SharedPreferences widgetPreferences = preferences(context);
        String storedBinding = widgetPreferences.getString(preferenceKey, null);
        String entryId = decodeEntryBinding(storedBinding);
        VaultState.Entry entry = null;
        if (entryId != null) {
            try {
                entry = new VaultStore(context).load().findEntry(entryId);
                if (entry == null) {
                    widgetPreferences.edit()
                            .putString(preferenceKey, BINDING_CHOOSE_EACH_TIME)
                            .apply();
                } else if (entryId.equals(storedBinding)) {
                    // Migrate the untagged binding used by earlier releases without changing its target.
                    widgetPreferences.edit()
                            .putString(preferenceKey, BINDING_ENTRY_PREFIX + entryId)
                            .apply();
                }
            } catch (VaultException ignored) {
            }
        } else if (!BINDING_CHOOSE_EACH_TIME.equals(storedBinding)) {
            // A newly restored or storage-cleared widget becomes an explicit picker widget.
            widgetPreferences.edit()
                    .putString(preferenceKey, BINDING_CHOOSE_EACH_TIME)
                    .apply();
        }
        Intent click;
        if (entry != null) {
            click = RunEntryActivity.createIntent(context, entry.id)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        } else {
            click = WidgetCommandPickerActivity.createIntent(context)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        }
        PendingIntent pending = PendingIntent.getActivity(context, widgetId, click,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        if (Build.VERSION.SDK_INT >= 31) {
            updateExactSizeWidget(context, manager, widgetId, entry, pending);
        } else {
            Bundle options = manager.getAppWidgetOptions(widgetId);
            int minWidth = options.getInt(AppWidgetManager.OPTION_APPWIDGET_MIN_WIDTH, 40);
            int minHeight = options.getInt(AppWidgetManager.OPTION_APPWIDGET_MIN_HEIGHT, 40);
            int layout = minWidth >= 120 && minHeight < 72
                    ? R.layout.widget_command : R.layout.widget_command_compact;
            manager.updateAppWidget(widgetId,
                    createViews(context, layout, entry, pending, null));
        }
    }

    private static void updateExactSizeWidget(Context context, AppWidgetManager manager,
                                              int widgetId, VaultState.Entry entry,
                                              PendingIntent pending) {
        if (Build.VERSION.SDK_INT < 31) return;
        Bundle options = manager.getAppWidgetOptions(widgetId);
        Map<SizeF, RemoteViews> layouts = new ArrayMap<>();
        ArrayList<SizeF> reportedSizes = readReportedSizes(options);
        if (reportedSizes != null) {
            for (SizeF size : reportedSizes) {
                addSizeVariant(context, layouts, size, entry, pending);
            }
        }

        if (layouts.isEmpty()) {
            float minWidth = positiveOption(options, AppWidgetManager.OPTION_APPWIDGET_MIN_WIDTH,
                    WidgetGeometry.DEFAULT_PORTRAIT_WIDTH_DP);
            float maxWidth = positiveOption(options, AppWidgetManager.OPTION_APPWIDGET_MAX_WIDTH,
                    WidgetGeometry.DEFAULT_LANDSCAPE_WIDTH_DP);
            float minHeight = positiveOption(options, AppWidgetManager.OPTION_APPWIDGET_MIN_HEIGHT,
                    WidgetGeometry.DEFAULT_LANDSCAPE_HEIGHT_DP);
            float maxHeight = positiveOption(options, AppWidgetManager.OPTION_APPWIDGET_MAX_HEIGHT,
                    WidgetGeometry.DEFAULT_PORTRAIT_HEIGHT_DP);
            addSizeVariant(context, layouts, new SizeF(minWidth, maxHeight), entry, pending);
            addSizeVariant(context, layouts, new SizeF(maxWidth, minHeight), entry, pending);
        }

        if (layouts.isEmpty()) {
            SizeF fallback = new SizeF(WidgetGeometry.DEFAULT_PORTRAIT_WIDTH_DP,
                    WidgetGeometry.DEFAULT_PORTRAIT_HEIGHT_DP);
            addSizeVariant(context, layouts, fallback, entry, pending);
        }
        manager.updateAppWidget(widgetId, new RemoteViews(layouts));
    }

    private static void addSizeVariant(Context context, Map<SizeF, RemoteViews> layouts,
                                       SizeF size, VaultState.Entry entry, PendingIntent pending) {
        if (Build.VERSION.SDK_INT < 31) return;
        if (size == null || !WidgetGeometry.isUsableHostSize(
                size.getWidth(), size.getHeight()) || layouts.containsKey(size)) return;
        float side = WidgetGeometry.tileSideDp(size.getWidth(), size.getHeight());
        layouts.put(size, createViews(
                context, R.layout.widget_command_compact, entry, pending, side));
    }

    @SuppressWarnings("deprecation")
    private static ArrayList<SizeF> readReportedSizes(Bundle options) {
        if (Build.VERSION.SDK_INT < 31 || options == null) return null;
        if (Build.VERSION.SDK_INT >= 33) {
            return options.getParcelableArrayList(
                    AppWidgetManager.OPTION_APPWIDGET_SIZES, SizeF.class);
        }
        return options.getParcelableArrayList(AppWidgetManager.OPTION_APPWIDGET_SIZES);
    }

    private static float positiveOption(Bundle options, String key, float fallback) {
        if (options == null) return fallback;
        int value = options.getInt(key, Math.round(fallback));
        return value > 0 ? value : fallback;
    }

    private static RemoteViews createViews(Context context, int layout,
                                           VaultState.Entry entry, PendingIntent pending,
                                           Float tileSideDp) {
        RemoteViews views = new RemoteViews(context.getPackageName(), layout);
        if (entry != null) {
            views.setTextViewText(R.id.widget_icon, EntryIcons.glyph(entry.icon));
            String safeTitle = TextPolicy.safeDisplayTitle(entry.title);
            views.setTextViewText(R.id.widget_title, safeTitle);
            views.setContentDescription(R.id.widget_root, "Run " + safeTitle);
        } else {
            views.setTextViewText(R.id.widget_icon, "×");
            views.setTextViewText(R.id.widget_title, "Choose command");
            views.setContentDescription(R.id.widget_root, "Choose a protected command");
        }
        if (Build.VERSION.SDK_INT >= 31 && tileSideDp != null) {
            float side = tileSideDp;
            views.setViewLayoutWidth(android.R.id.background, side, TypedValue.COMPLEX_UNIT_DIP);
            views.setViewLayoutHeight(android.R.id.background, side, TypedValue.COMPLEX_UNIT_DIP);
            views.setTextViewTextSize(R.id.widget_title, TypedValue.COMPLEX_UNIT_SP,
                    WidgetGeometry.titleTextSp(side));
            views.setTextViewTextSize(R.id.widget_icon, TypedValue.COMPLEX_UNIT_SP,
                    WidgetGeometry.glyphTextSp(side));
            views.setInt(R.id.widget_title, "setMaxLines", WidgetGeometry.titleMaxLines(side));
        }
        views.setOnClickPendingIntent(R.id.widget_root, pending);
        return views;
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
    }

    static String encodeEntryBinding(String entryId) {
        return isUuid(entryId) ? BINDING_ENTRY_PREFIX + entryId : null;
    }

    static String decodeEntryBinding(String binding) {
        if (binding == null || BINDING_CHOOSE_EACH_TIME.equals(binding)) return null;
        String candidate = binding.startsWith(BINDING_ENTRY_PREFIX)
                ? binding.substring(BINDING_ENTRY_PREFIX.length())
                : binding;
        return isUuid(candidate) ? candidate : null;
    }

    private static boolean isUuid(String value) {
        if (value == null || value.length() != 36) return false;
        try {
            return value.equals(UUID.fromString(value).toString());
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }
}
