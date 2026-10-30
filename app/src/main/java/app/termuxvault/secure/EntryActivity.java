package app.termuxvault.secure;

import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import java.nio.charset.CharacterCodingException;

public final class EntryActivity extends SecureActivity {
    private static final String EXTRA_ID = "entry_id";
    private byte[] vmk;
    private byte[] vaultFingerprint;
    private String entryId;
    private EditText titleField;
    private EditText commandField;
    private Spinner iconSpinner;
    private CheckBox pauseAfterRun;
    private CheckBox notifyWhenFinished;
    private CheckBox hideTerminalOutput;

    static Intent createIntent(Context context, String id) {
        Intent intent = new Intent(context, EntryActivity.class);
        if (id != null) intent.putExtra(EXTRA_ID, id);
        return intent;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        entryId = getIntent().getStringExtra(EXTRA_ID);
        LinearLayout loading = Ui.page(this);
        loading.setGravity(Gravity.CENTER);
        loading.addView(Ui.text(this, "Authentication required", 18, Ui.MUTED));
        setContentView(loading);
        UnlockCoordinator.ReasonResolver reason = entryId == null
                ? ignored -> AuthorizationReason.createCommand()
                : UnlockCoordinator.entryReason(entryId, UnlockCoordinator.EntryAction.EDIT);
        UnlockCoordinator.unlock(this, reason,
                new UnlockCoordinator.Callback() {
                    @Override
                    public void onUnlocked(byte[] key, byte[] fingerprint) {
                        vmk = key;
                        vaultFingerprint = fingerprint;
                        loadEditor();
                    }

                    @Override
                    public void onCancelled() {
                        finish();
                    }
                });
    }

    private void loadEditor() {
        VaultState.Entry entry = null;
        char[] commandChars = null;
        byte[] commandBytes = null;
        try {
            OpenedEntry opened = new VaultStore(this).readIfUnchanged(
                    vaultFingerprint, state -> {
                        if (entryId == null) return new OpenedEntry(null, null);
                        VaultState.Entry current = state.findEntry(entryId);
                        if (current == null) throw new VaultException("Entry no longer exists");
                        return new OpenedEntry(current, VaultService.decryptEntry(vmk, current));
                    });
            entry = opened.entry;
            commandBytes = opened.command;
            if (commandBytes != null) commandChars = CryptoEngine.utf8ToChars(commandBytes);
            buildEditor(entry, commandChars);
        } catch (VaultException | CharacterCodingException exception) {
            CryptoEngine.wipe(vmk);
            vmk = null;
            CryptoEngine.wipe(vaultFingerprint);
            vaultFingerprint = null;
            Ui.showSecure(new android.app.AlertDialog.Builder(this)
                    .setTitle("Command unavailable")
                    .setMessage("The protected command could not be opened.")
                    .setPositiveButton("Close", (dialog, which) -> finish())
                    .setOnCancelListener(dialog -> finish()));
        } finally {
            CryptoEngine.wipe(commandBytes);
            CryptoEngine.wipe(commandChars);
        }
    }

    private void buildEditor(VaultState.Entry entry, char[] commandChars) {
        ScrollView scroll = new ScrollView(this);
        LinearLayout page = Ui.page(this);
        scroll.addView(page);
        page.addView(Ui.title(this, entry == null ? "New command" : "Edit command"),
                Ui.matchWrap());

        titleField = Ui.textField(this, "Title", false);
        if (entry != null) titleField.setText(entry.title);
        titleField.setSaveEnabled(false);
        page.addView(titleField, Ui.matchWrap());
        Ui.addSpace(page, 8);

        iconSpinner = new Spinner(this);
        ArrayAdapter<String> icons = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_dropdown_item, EntryIcons.labels());
        iconSpinner.setAdapter(icons);
        if (entry != null) {
            String[] ids = EntryIcons.ids();
            for (int i = 0; i < ids.length; i++) if (ids[i].equals(entry.icon)) iconSpinner.setSelection(i);
        }
        page.addView(iconSpinner, Ui.matchWrap());
        Ui.addSpace(page, 10);

        commandField = new CommandEditText(this);
        Ui.setCompactHint(commandField, "Termux command");
        commandField.setHintTextColor(Ui.MUTED);
        commandField.setTextColor(Ui.TEXT);
        commandField.setTypeface(Typeface.MONOSPACE);
        commandField.setGravity(Gravity.TOP | Gravity.START);
        commandField.setMinLines(12);
        commandField.setSingleLine(false);
        commandField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        commandField.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                | EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        if (commandChars != null) commandField.setText(commandChars, 0, commandChars.length);
        page.addView(commandField, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 280)));
        Ui.addSpace(page, 8);

        pauseAfterRun = new CheckBox(this);
        pauseAfterRun.setText(R.string.pause_after_run);
        pauseAfterRun.setTextColor(Ui.TEXT);
        pauseAfterRun.setChecked(entry != null && entry.pauseAfterRun);
        pauseAfterRun.setFilterTouchesWhenObscured(true);
        page.addView(pauseAfterRun, Ui.matchWrap());
        page.addView(Ui.text(this,
                "Every run shows a final result. Failures wait for Enter automatically; enable "
                        + "this to keep a successful session open too.",
                13, Ui.MUTED), Ui.matchWrap());
        Ui.addSpace(page, 10);

        hideTerminalOutput = new CheckBox(this);
        hideTerminalOutput.setText(R.string.hide_terminal_output);
        hideTerminalOutput.setTextColor(Ui.TEXT);
        hideTerminalOutput.setChecked(entry != null && entry.hideTerminalOutput);
        hideTerminalOutput.setFilterTouchesWhenObscured(true);
        page.addView(hideTerminalOutput, Ui.matchWrap());
        page.addView(Ui.text(this,
                "Suppresses the command's normal output and errors. The non-sensitive title and "
                        + "generic final result remain visible. This may hide interactive prompts.",
                13, Ui.MUTED), Ui.matchWrap());
        Ui.addSpace(page, 10);

        notifyWhenFinished = new CheckBox(this);
        notifyWhenFinished.setText(R.string.notify_when_finished);
        notifyWhenFinished.setTextColor(Ui.TEXT);
        notifyWhenFinished.setChecked(entry != null && entry.notifyWhenFinished);
        notifyWhenFinished.setFilterTouchesWhenObscured(true);
        page.addView(notifyWhenFinished, Ui.matchWrap());
        page.addView(Ui.text(this,
                "Posts only the title and aggregate outcome. Tap the notification to reopen Termux. "
                        + "Android notification permission is required.",
                13, Ui.MUTED), Ui.matchWrap());
        Ui.addSpace(page, 14);

        Button action = Ui.button(this, "Save command");
        action.setOnClickListener(view -> save());
        page.addView(action, Ui.matchWrap());
        setContentView(scroll);
    }

    private void save() {
        String title = titleField.getText().toString().trim();
        if (title.isEmpty() || title.length() > 80) {
            Ui.showError(this, "Use a title of 1 to 80 characters.");
            return;
        }
        char[] command = Ui.readChars(commandField);
        String[] ids = EntryIcons.ids();
        String icon = ids[Math.max(0, Math.min(iconSpinner.getSelectedItemPosition(), ids.length - 1))];
        boolean shouldPause = pauseAfterRun.isChecked();
        boolean shouldNotify = notifyWhenFinished.isChecked();
        boolean shouldHideOutput = hideTerminalOutput.isChecked();
        try {
            String[] savedEntryId = {entryId};
            new VaultStore(this).mutateIfUnchanged(vaultFingerprint, state -> {
                if (savedEntryId[0] == null) {
                    if (state.entries.size() >= VaultStore.MAX_ENTRIES) {
                        throw new VaultException("The vault is full");
                    }
                    VaultState.Entry entry = VaultService.encryptNewEntry(
                            vmk, title, icon, command, shouldPause, shouldNotify,
                            shouldHideOutput);
                    state.entries.add(entry);
                    savedEntryId[0] = entry.id;
                } else {
                    VaultState.Entry entry = state.findEntry(savedEntryId[0]);
                    if (entry == null) throw new VaultException("Entry no longer exists");
                    VaultService.updateEntry(vmk, entry, title, icon, command, shouldPause,
                            shouldNotify, shouldHideOutput);
                }
            });
            entryId = savedEntryId[0];
            CommandWidgetProvider.refreshAll(this);
            wipeAndFinish();
        } catch (VaultException exception) {
            Ui.showError(this, exception.getMessage());
        } finally {
            CryptoEngine.wipe(command);
        }
    }

    private void wipeAndFinish() {
        CryptoEngine.wipe(vmk);
        vmk = null;
        CryptoEngine.wipe(vaultFingerprint);
        vaultFingerprint = null;
        if (commandField != null) Ui.clear(commandField);
        finish();
    }

    @Override
    protected void onSecureForegroundLost() {
        wipeAndFinish();
    }

    @Override
    protected void onDestroy() {
        CryptoEngine.wipe(vmk);
        vmk = null;
        CryptoEngine.wipe(vaultFingerprint);
        vaultFingerprint = null;
        if (commandField != null) Ui.clear(commandField);
        super.onDestroy();
    }

    private static final class OpenedEntry {
        final VaultState.Entry entry;
        final byte[] command;

        OpenedEntry(VaultState.Entry entry, byte[] command) {
            this.entry = entry;
            this.command = command;
        }
    }
}
