package app.termuxvault.secure;

import android.content.Context;
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

/** Selects a current vault entry without changing the widget's choose-each-time binding. */
public final class WidgetCommandPickerActivity extends SecureActivity {
    private final List<VaultState.Entry> entries = new ArrayList<>();

    static Intent createIntent(Context context) {
        return new Intent(context, WidgetCommandPickerActivity.class);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout page = Ui.page(this);
        page.addView(Ui.title(this, "Choose a command"), Ui.matchWrap());
        try {
            entries.addAll(new VaultStore(this).load().entries);
        } catch (VaultException exception) {
            TextView unavailable = Ui.text(this,
                    "Open Termux Vault and create a command first.", 15, Ui.MUTED);
            page.addView(unavailable, Ui.matchWrap());
            setContentView(page);
            return;
        }

        if (entries.isEmpty()) {
            TextView empty = Ui.text(this,
                    "No protected commands are available.", 15, Ui.MUTED);
            page.addView(empty, Ui.matchWrap());
        } else {
            ListView list = new ListView(this);
            list.setDividerHeight(0);
            list.setAdapter(new EntryAdapter());
            list.setOnItemClickListener((parent, view, position, id) -> {
                VaultState.Entry entry = entries.get(position);
                startActivity(RunEntryActivity.createIntent(this, entry.id));
                finish();
            });
            page.addView(list, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        }
        setContentView(page);
    }

    private final class EntryAdapter extends BaseAdapter {
        @Override
        public int getCount() {
            return entries.size();
        }

        @Override
        public VaultState.Entry getItem(int position) {
            return entries.get(position);
        }

        @Override
        public long getItemId(int position) {
            return getItem(position).id.hashCode();
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            VaultState.Entry entry = getItem(position);
            LinearLayout row = new LinearLayout(WidgetCommandPickerActivity.this);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(Ui.dp(WidgetCommandPickerActivity.this, 8),
                    Ui.dp(WidgetCommandPickerActivity.this, 14),
                    Ui.dp(WidgetCommandPickerActivity.this, 8),
                    Ui.dp(WidgetCommandPickerActivity.this, 14));
            TextView icon = Ui.text(WidgetCommandPickerActivity.this,
                    EntryIcons.glyph(entry.icon), 20, Ui.ACCENT);
            row.addView(icon, new LinearLayout.LayoutParams(
                    Ui.dp(WidgetCommandPickerActivity.this, 48),
                    ViewGroup.LayoutParams.WRAP_CONTENT));
            row.addView(Ui.text(WidgetCommandPickerActivity.this,
                            TextPolicy.safeDisplayTitle(entry.title), 17, Ui.TEXT),
                    new LinearLayout.LayoutParams(0,
                            ViewGroup.LayoutParams.WRAP_CONTENT, 1));
            return row;
        }
    }
}
