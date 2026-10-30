package app.termuxvault.secure;

import android.appwidget.AppWidgetManager;
import android.content.Intent;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

public final class WidgetConfigActivity extends SecureActivity {
    private final List<VaultState.Entry> entries = new ArrayList<>();
    private int widgetId = AppWidgetManager.INVALID_APPWIDGET_ID;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setResult(RESULT_CANCELED);
        widgetId = getIntent().getIntExtra(AppWidgetManager.EXTRA_APPWIDGET_ID,
                AppWidgetManager.INVALID_APPWIDGET_ID);
        if (widgetId == AppWidgetManager.INVALID_APPWIDGET_ID) {
            finish();
            return;
        }
        try {
            entries.addAll(new VaultStore(this).load().entries);
        } catch (VaultException ignored) {
            // Choose-each-time remains a valid configuration before the vault has entries.
        }

        LinearLayout page = Ui.page(this);
        page.addView(Ui.title(this, "Configure widget"), Ui.matchWrap());
        ListView list = new ListView(this);
        list.setDividerHeight(0);
        list.setAdapter(new WidgetEntryAdapter());
        list.setOnItemClickListener((parent, view, position, id) -> {
            if (position == 0) selectChooseEachTime();
            else select(entries.get(position - 1).id);
        });
        page.addView(list, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        setContentView(page);
    }

    private void selectChooseEachTime() {
        CommandWidgetProvider.assignChooseEachTime(this, widgetId);
        completeConfiguration();
    }

    private void select(String entryId) {
        CommandWidgetProvider.assign(this, widgetId, entryId);
        completeConfiguration();
    }

    private void completeConfiguration() {
        Intent result = new Intent().putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, widgetId);
        setResult(RESULT_OK, result);
        finish();
    }

    private final class WidgetEntryAdapter extends BaseAdapter {
        @Override
        public int getCount() {
            return entries.size() + 1;
        }

        @Override
        public VaultState.Entry getItem(int position) {
            return position == 0 ? null : entries.get(position - 1);
        }

        @Override
        public long getItemId(int position) {
            VaultState.Entry entry = getItem(position);
            return entry == null ? 0 : entry.id.hashCode();
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            VaultState.Entry entry = getItem(position);
            LinearLayout row = new LinearLayout(WidgetConfigActivity.this);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(Ui.dp(WidgetConfigActivity.this, 8), Ui.dp(WidgetConfigActivity.this, 14),
                    Ui.dp(WidgetConfigActivity.this, 8), Ui.dp(WidgetConfigActivity.this, 14));
            TextView icon = Ui.text(WidgetConfigActivity.this,
                    entry == null ? "?" : EntryIcons.glyph(entry.icon), 20, Ui.ACCENT);
            row.addView(icon, new LinearLayout.LayoutParams(Ui.dp(WidgetConfigActivity.this, 48),
                    ViewGroup.LayoutParams.WRAP_CONTENT));
            if (entry == null) {
                LinearLayout labels = new LinearLayout(WidgetConfigActivity.this);
                labels.setOrientation(LinearLayout.VERTICAL);
                labels.addView(Ui.text(WidgetConfigActivity.this,
                        "Choose each time", 17, Ui.TEXT), Ui.matchWrap());
                labels.addView(Ui.text(WidgetConfigActivity.this,
                        "Select a protected command whenever you tap the widget.",
                        14, Ui.MUTED), Ui.matchWrap());
                row.addView(labels, new LinearLayout.LayoutParams(
                        0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
            } else {
                row.addView(Ui.text(WidgetConfigActivity.this,
                                TextPolicy.safeDisplayTitle(entry.title), 17, Ui.TEXT),
                        new LinearLayout.LayoutParams(0,
                                ViewGroup.LayoutParams.WRAP_CONTENT, 1));
            }
            return row;
        }
    }
}
