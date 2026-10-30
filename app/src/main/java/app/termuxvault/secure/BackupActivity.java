package app.termuxvault.secure;

import android.annotation.SuppressLint;
import android.app.AlertDialog;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.os.Bundle;
import android.text.InputFilter;
import android.text.InputType;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewStructure;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.Arrays;

@SuppressLint("SetTextI18n")
public final class BackupActivity extends SecureActivity {
    enum Mode {
        EXPORT_ENCRYPTED,
        IMPORT,
        EXPORT_PLAINTEXT
    }

    private static final String EXTRA_MODE = "mode";
    private static final int MAX_BACKUP_TEXT_CHARS = 12 * 1024 * 1024;

    private Mode mode;
    private boolean busy;
    private BackupCodec.Bundle pendingImport;
    private EditText importText;
    private AlertDialog importPassphraseDialog;
    private PasswordInput importDialogPassphraseInput;
    private PasswordInput exportVaultPassphraseInput;
    private PasswordInput exportBackupPassphraseInput;
    private PasswordInput exportConfirmationPassphraseInput;
    private EditText exportResultText;

    static Intent intent(Context context, Mode mode) {
        return new Intent(context, BackupActivity.class).putExtra(EXTRA_MODE, mode.name());
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            mode = Mode.valueOf(getIntent().getStringExtra(EXTRA_MODE));
        } catch (RuntimeException exception) {
            finish();
            return;
        }
        if (mode == Mode.EXPORT_ENCRYPTED) {
            showEncryptedExport();
        } else if (mode == Mode.EXPORT_PLAINTEXT) {
            showPlaintextExport();
        } else {
            showImport();
        }
    }

    private void showEncryptedExport() {
        LinearLayout page = newPage("Export encrypted backup");
        page.addView(Ui.text(this,
                "This creates portable encrypted text containing every command. Verify the vault "
                        + "passphrase, then choose what passphrase will protect the backup.",
                14, Ui.MUTED), Ui.matchWrap());
        Ui.addSpace(page, 8);
        page.addView(Ui.text(this,
                "The backup passphrase directly encrypts this portable backup. Anyone who obtains "
                        + "the backup can attempt to guess it offline. There is no recovery if you "
                        + "forget it.\n\n" + PassphraseWarning.guidance(),
                14, Ui.MUTED), Ui.matchWrap());
        Ui.addSpace(page, 12);

        PasswordInput vaultInput = passwordField("Vault passphrase");
        exportVaultPassphraseInput = vaultInput;
        page.addView(vaultInput, Ui.matchWrap());
        Ui.addSpace(page, 8);

        RadioGroup choices = new RadioGroup(this);
        choices.setOrientation(RadioGroup.VERTICAL);
        RadioButton newSecret = radio("Use a different backup passphrase (recommended)");
        RadioButton vaultSecret = radio("Use the vault passphrase");
        choices.addView(newSecret, Ui.matchWrap());
        choices.addView(vaultSecret, Ui.matchWrap());
        newSecret.setChecked(true);
        page.addView(choices, Ui.matchWrap());
        Ui.addSpace(page, 8);

        PasswordInput backupInput = passwordField("New backup passphrase");
        PasswordInput confirmationInput = passwordField("Confirm backup passphrase");
        exportBackupPassphraseInput = backupInput;
        exportConfirmationPassphraseInput = confirmationInput;
        page.addView(backupInput, Ui.matchWrap());
        page.addView(confirmationInput, Ui.matchWrap());

        choices.setOnCheckedChangeListener((group, checkedId) -> {
            int visibility = newSecret.isChecked() ? View.VISIBLE : View.GONE;
            backupInput.setVisibility(visibility);
            confirmationInput.setVisibility(visibility);
            if (visibility == View.GONE) {
                Ui.clear(backupInput.editText());
                Ui.clear(confirmationInput.editText());
            }
        });

        TextView status = Ui.text(this, "", 13, Ui.DANGER);
        page.addView(status, Ui.matchWrap());
        Button create = Ui.button(this, "Create encrypted backup");
        create.setOnClickListener(view -> {
            if (busy) return;
            char[] vaultPassphrase = Ui.readChars(vaultInput.editText());
            char[] backupPassphrase;
            char[] confirmation = null;
            if (newSecret.isChecked()) {
                backupPassphrase = Ui.readChars(backupInput.editText());
                confirmation = Ui.readChars(confirmationInput.editText());
                if (backupPassphrase.length == 0
                        || !Arrays.equals(backupPassphrase, confirmation)) {
                    wipeAll(vaultPassphrase, backupPassphrase, confirmation);
                    status.setText("Use matching, non-empty backup passphrases.");
                    return;
                }
            } else {
                backupPassphrase = Arrays.copyOf(vaultPassphrase, vaultPassphrase.length);
            }
            CryptoEngine.wipe(confirmation);
            Ui.clear(vaultInput.editText());
            Ui.clear(backupInput.editText());
            Ui.clear(confirmationInput.editText());
            if (vaultPassphrase.length == 0) {
                wipeAll(vaultPassphrase, backupPassphrase);
                status.setText("Vault passphrase is incorrect.");
                return;
            }
            if (PassphraseWarning.isTooWeak(backupPassphrase)) {
                PassphraseWarning.show(this, PassphraseWarning.Purpose.BACKUP, useAnyway -> {
                    if (!useAnyway) {
                        wipeAll(vaultPassphrase, backupPassphrase);
                        if (isSecureSessionActive()) {
                            status.setText("Choose a stronger backup passphrase.");
                            backupInput.editText().post(() -> {
                                EditText first = backupInput.editText();
                                if (!isSecureSessionActive()
                                        || !newSecret.isChecked()
                                        || !first.isShown()) return;
                                first.requestFocus();
                                first.setSelection(0);
                            });
                        }
                        return;
                    }
                    startEncryptedExport(vaultPassphrase, backupPassphrase, create, status);
                });
                return;
            }
            startEncryptedExport(vaultPassphrase, backupPassphrase, create, status);
        });
        page.addView(create, Ui.matchWrap());
        addClose(page);
    }

    private void startEncryptedExport(char[] vaultPassphrase, char[] backupPassphrase,
                                      Button create, TextView status) {
        if (isFinishing() || isDestroyed()) {
            wipeAll(vaultPassphrase, backupPassphrase);
            return;
        }
        setBusy(create, status, "Creating encrypted backup…");
        new Thread(() -> exportBackup(vaultPassphrase, backupPassphrase, true, create, status),
                "vault-backup-export").start();
    }

    private void showPlaintextExport() {
        LinearLayout page = newPage("Export unprotected readable backup");
        TextView warning = Ui.text(this,
                "DANGER: This creates readable JSON containing every command and password. It is "
                        + "not encrypted or authenticated. Anyone who sees the screen or clipboard "
                        + "can read or change it. Clear the clipboard when finished.",
                14, Ui.DANGER);
        warning.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        page.addView(warning, Ui.matchWrap());
        Ui.addSpace(page, 12);
        PasswordInput vaultInput = passwordField("Vault passphrase");
        exportVaultPassphraseInput = vaultInput;
        page.addView(vaultInput, Ui.matchWrap());
        TextView status = Ui.text(this, "", 13, Ui.DANGER);
        page.addView(status, Ui.matchWrap());
        Button create = Ui.button(this, "I understand — create readable backup");
        create.setOnClickListener(view -> {
            if (busy) return;
            char[] vaultPassphrase = Ui.readChars(vaultInput.editText());
            Ui.clear(vaultInput.editText());
            if (vaultPassphrase.length == 0) {
                CryptoEngine.wipe(vaultPassphrase);
                status.setText("Vault passphrase is incorrect.");
                return;
            }
            setBusy(create, status, "Creating readable backup…");
            new Thread(() -> exportBackup(vaultPassphrase, null, false, create, status),
                    "vault-readable-export").start();
        });
        page.addView(create, Ui.matchWrap());
        addClose(page);
    }

    private void exportBackup(char[] vaultPassphrase, char[] backupPassphrase,
                              boolean encrypted, Button create, TextView status) {
        char[] result = null;
        VaultException failure = null;
        try {
            result = new VaultStore(this).readLocked(state -> {
                byte[] vmk = VaultService.unlockWithPassphrase(state, vaultPassphrase);
                try {
                    return encrypted
                            ? BackupCodec.exportEncrypted(state, vmk, backupPassphrase)
                            : BackupCodec.exportPlaintext(state, vmk);
                } finally {
                    CryptoEngine.wipe(vmk);
                }
            });
        } catch (VaultException exception) {
            failure = exception;
        } finally {
            wipeAll(vaultPassphrase, backupPassphrase);
        }
        char[] output = result;
        VaultException finalFailure = failure;
        runOnUiThread(() -> {
            busy = false;
            if (isFinishing() || isDestroyed()) {
                CryptoEngine.wipe(output);
                return;
            }
            if (finalFailure != null) {
                CryptoEngine.wipe(output);
                create.setEnabled(true);
                status.setText(finalFailure.isAuthenticationFailure()
                        ? "Vault passphrase is incorrect."
                        : "The backup could not be created.");
                return;
            }
            showExportResult(output, encrypted);
        });
    }

    private void showExportResult(char[] output, boolean encrypted) {
        LinearLayout page = newPage(encrypted ? "Encrypted backup" : "Unprotected readable backup");
        page.addView(Ui.text(this, encrypted
                        ? "Copy this text and store it safely. The backup passphrase is not stored "
                                + "or recoverable by Termux Vault."
                        : "This JSON exposes every command in readable form. It has no encryption "
                                + "or authenticity protection. Clear the clipboard when finished.",
                14, encrypted ? Ui.MUTED : Ui.DANGER), Ui.matchWrap());
        Ui.addSpace(page, 10);
        SensitiveBackupResultEditText text = backupResultTextField();
        exportResultText = text;
        try {
            text.setText(output, 0, output.length);
        } finally {
            CryptoEngine.wipe(output);
        }
        page.addView(text, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, Ui.dp(this, 320)));
        Ui.addSpace(page, 8);
        TextView copied = Ui.text(this, "", 13, Ui.ACCENT);
        page.addView(copied, Ui.matchWrap());
        Button copy = Ui.button(this, "Copy backup text");
        copy.setOnClickListener(view -> {
            try {
                ClipboardManager clipboard = getSystemService(ClipboardManager.class);
                if (clipboard == null) throw new IllegalStateException("Clipboard unavailable");
                clipboard.setPrimaryClip(SensitiveClipboard.plainText(
                        "Termux Vault backup", text.getText()));
                copied.setTextColor(Ui.ACCENT);
                copied.setText("Copied. Clear the clipboard after storing the backup.");
            } catch (RuntimeException exception) {
                // Android's clipboard crosses Binder and can reject a very large valid backup.
                // Never crash or include the backup text in the error path.
                copied.setTextColor(Ui.DANGER);
                copied.setText("Android could not copy this backup. It may be too large for a "
                        + "single clipboard item.");
            }
        });
        page.addView(copy, Ui.matchWrap());
        Ui.addSpace(page, 8);
        Button close = Ui.button(this, "Close");
        close.setOnClickListener(view -> {
            Ui.clear(text);
            finish();
        });
        page.addView(close, Ui.matchWrap());
    }

    private void showImport() {
        LinearLayout page = newPage("Import backup");
        page.addView(Ui.text(this,
                "Paste an encrypted backup or an unprotected readable JSON backup. Valid entries "
                        + "are appended; existing entries are never replaced or removed.",
                14, Ui.MUTED), Ui.matchWrap());
        Ui.addSpace(page, 10);
        importText = backupImportTextField();
        Ui.setCompactHint(importText, "Paste backup text");
        importText.setFilters(new InputFilter[]{new InputFilter.LengthFilter(MAX_BACKUP_TEXT_CHARS)});
        page.addView(importText, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, Ui.dp(this, 280)));
        TextView status = Ui.text(this, "", 13, Ui.DANGER);
        page.addView(status, Ui.matchWrap());
        Button review = Ui.button(this, "Review backup");
        review.setOnClickListener(view -> reviewImport(review, status));
        page.addView(review, Ui.matchWrap());
        addClose(page);
    }

    private void reviewImport(Button review, TextView status) {
        if (busy) return;
        wipePendingImport();
        if (importText == null || importText.length() == 0) {
            status.setText("Paste a backup first.");
            return;
        }
        if (BackupCodec.isEncrypted(importText.getText())) {
            showEncryptedImportPassphraseDialog(review, status);
            return;
        }
        char[] text = Ui.readChars(importText);
        Ui.clear(importText);
        setBusy(review, status, "Validating backup…");
        decodeImport(text, null, false, review, status, null, null);
    }

    private void showEncryptedImportPassphraseDialog(Button review, TextView pageStatus) {
        if (importPassphraseDialog != null && importPassphraseDialog.isShowing()) return;
        review.setEnabled(false);
        pageStatus.setText("");
        LinearLayout body = Ui.page(this);
        body.setPadding(Ui.dp(this, 20), Ui.dp(this, 8), Ui.dp(this, 20), 0);
        body.addView(Ui.text(this,
                "This backup is encrypted. Enter the passphrase that was used when it was created.",
                14, Ui.MUTED), Ui.matchWrap());
        Ui.addSpace(body, 8);
        PasswordInput passphraseInput = passwordField("Backup passphrase");
        importDialogPassphraseInput = passphraseInput;
        body.addView(passphraseInput, Ui.matchWrap());
        TextView dialogStatus = Ui.text(this, "", 13, Ui.DANGER);
        body.addView(dialogStatus, Ui.matchWrap());

        AlertDialog dialog = Ui.createSecure(new AlertDialog.Builder(this)
                .setTitle("Encrypted backup")
                .setView(body)
                .setPositiveButton("Decrypt", null)
                .setNegativeButton("Cancel", null));
        importPassphraseDialog = dialog;
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE)
                .setOnClickListener(view -> {
                    char[] passphrase = Ui.readChars(passphraseInput.editText());
                    Ui.clear(passphraseInput.editText());
                    if (passphrase.length == 0) {
                        CryptoEngine.wipe(passphrase);
                        dialogStatus.setText("Enter the backup passphrase.");
                        return;
                    }
                    char[] text = Ui.readChars(importText);
                    if (text.length == 0) {
                        wipeAll(text, passphrase);
                        dialogStatus.setText("Paste a backup first.");
                        return;
                    }
                    setBusy(review, pageStatus, "Decrypting encrypted backup…");
                    dialog.setCancelable(false);
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);
                    dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setEnabled(false);
                    dialogStatus.setText("Decrypting…");
                    decodeImport(text, passphrase, true, review, pageStatus,
                            dialog, dialogStatus);
                }));
        dialog.setOnDismissListener(ignored -> {
            Ui.clear(passphraseInput.editText());
            if (importPassphraseDialog == dialog) {
                importPassphraseDialog = null;
                importDialogPassphraseInput = null;
            }
            if (!busy && !isFinishing() && !isDestroyed()) review.setEnabled(true);
        });
        dialog.show();
    }

    private void decodeImport(char[] text, char[] passphrase, boolean encrypted,
                              Button review, TextView pageStatus, AlertDialog passphraseDialog,
                              TextView dialogStatus) {
        new Thread(() -> {
            BackupCodec.Bundle decoded = null;
            VaultException failure = null;
            try {
                decoded = BackupCodec.decode(text, encrypted ? passphrase : null);
            } catch (VaultException exception) {
                failure = exception;
            } finally {
                wipeAll(text, passphrase);
            }
            BackupCodec.Bundle result = decoded;
            VaultException finalFailure = failure;
            runOnUiThread(() -> {
                busy = false;
                if (isFinishing() || isDestroyed()) {
                    if (result != null) result.wipe();
                    return;
                }
                review.setEnabled(true);
                if (finalFailure != null) {
                    if (passphraseDialog != null && passphraseDialog.isShowing()) {
                        passphraseDialog.setCancelable(true);
                        passphraseDialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(true);
                        passphraseDialog.getButton(AlertDialog.BUTTON_NEGATIVE).setEnabled(true);
                        dialogStatus.setText(finalFailure.getMessage());
                        pageStatus.setText("");
                    } else {
                        pageStatus.setText(finalFailure.getMessage());
                    }
                    return;
                }
                if (encrypted) Ui.clear(importText);
                if (passphraseDialog != null && passphraseDialog.isShowing()) {
                    passphraseDialog.dismiss();
                }
                pageStatus.setText("");
                pendingImport = result;
                confirmImport();
            });
        }, encrypted ? "vault-backup-decrypt" : "vault-backup-parse").start();
    }

    private void confirmImport() {
        BackupCodec.Bundle bundle = pendingImport;
        if (bundle == null) return;
        int count = bundle.size();
        if (count == 0) {
            wipePendingImport();
            Ui.showSecure(new AlertDialog.Builder(this)
                    .setTitle("Backup is empty")
                    .setMessage("The backup is valid and contains no entries. Nothing was changed.")
                    .setPositiveButton("OK", null));
            return;
        }
        Ui.showSecure(new AlertDialog.Builder(this)
                .setTitle("Import " + count + (count == 1 ? " entry?" : " entries?"))
                .setMessage("All entries will be appended in backup order. Duplicate titles and "
                        + "commands are allowed. Each imported entry receives a new internal ID; "
                        + "titles and command settings stay unchanged. Existing entries are untouched.")
                .setPositiveButton("Authenticate and import", (dialog, which) -> authenticateImport())
                .setNegativeButton("Cancel", (dialog, which) -> wipePendingImport())
                .setOnCancelListener(dialog -> wipePendingImport()));
    }

    private void authenticateImport() {
        if (pendingImport == null || busy) return;
        busy = true;
        UnlockCoordinator.unlock(this, AuthorizationReason.importCommands(pendingImport.size()),
                new UnlockCoordinator.Callback() {
            @Override
            public void onUnlocked(byte[] vmk, byte[] vaultFingerprint) {
                BackupCodec.Bundle bundle = pendingImport;
                pendingImport = null;
                if (bundle == null) {
                    CryptoEngine.wipe(vmk);
                    CryptoEngine.wipe(vaultFingerprint);
                    busy = false;
                    return;
                }
                new Thread(() -> importBundle(vmk, vaultFingerprint, bundle),
                        "vault-backup-import").start();
            }

            @Override
            public void onCancelled() {
                busy = false;
                wipePendingImport();
            }
        });
    }

    private void importBundle(byte[] vmk, byte[] vaultFingerprint, BackupCodec.Bundle bundle) {
        VaultException failure = null;
        int count = bundle.size();
        try {
            BackupCodec.appendToVault(new VaultStore(this), vmk, vaultFingerprint, bundle);
        } catch (VaultException exception) {
            failure = exception;
        } finally {
            CryptoEngine.wipe(vmk);
            CryptoEngine.wipe(vaultFingerprint);
            bundle.wipe();
        }
        VaultException finalFailure = failure;
        runOnUiThread(() -> {
            busy = false;
            if (isFinishing() || isDestroyed()) return;
            if (finalFailure != null) {
                Ui.showError(this, finalFailure.getMessage());
                return;
            }
            CommandWidgetProvider.refreshAll(this);
            Ui.showSecure(new AlertDialog.Builder(this)
                    .setTitle("Import complete")
                    .setMessage(count + (count == 1 ? " entry was" : " entries were")
                            + " appended to the vault.")
                    .setPositiveButton("Close", (dialog, which) -> finish()));
        });
    }

    private LinearLayout newPage(String title) {
        clearTrackedSensitiveViews();
        ScrollView scroll = new ScrollView(this);
        LinearLayout page = Ui.page(this);
        scroll.addView(page);
        page.addView(Ui.title(this, title), Ui.matchWrap());
        setContentView(scroll);
        return page;
    }

    private PasswordInput passwordField(String hint) {
        PasswordInput input = new PasswordInput(this, hint);
        input.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                | EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        return input;
    }

    private RadioButton radio(String label) {
        RadioButton button = new RadioButton(this);
        button.setId(View.generateViewId());
        button.setText(label);
        button.setTextColor(Ui.TEXT);
        button.setFilterTouchesWhenObscured(true);
        button.setSaveEnabled(false);
        return button;
    }

    private CommandEditText backupImportTextField() {
        CommandEditText field = new CommandEditText(this);
        field.setTextColor(Ui.TEXT);
        field.setHintTextColor(Ui.MUTED);
        field.setGravity(Gravity.TOP | Gravity.START);
        field.setSingleLine(false);
        field.setHorizontallyScrolling(false);
        field.setSaveEnabled(false);
        field.setTextIsSelectable(true);
        field.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        field.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                | EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        return field;
    }

    private SensitiveBackupResultEditText backupResultTextField() {
        SensitiveBackupResultEditText field = new SensitiveBackupResultEditText(this);
        field.setTextColor(Ui.TEXT);
        field.setHintTextColor(Ui.MUTED);
        field.setGravity(Gravity.TOP | Gravity.START);
        field.setSingleLine(false);
        field.setHorizontallyScrolling(false);
        field.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        field.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                | EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        return field;
    }

    private void addClose(LinearLayout page) {
        Ui.addSpace(page, 8);
        Button close = Ui.button(this, "Close");
        close.setOnClickListener(view -> finish());
        page.addView(close, Ui.matchWrap());
    }

    private void setBusy(Button button, TextView status, String message) {
        busy = true;
        button.setEnabled(false);
        status.setText(message);
    }

    private void wipePendingImport() {
        BackupCodec.Bundle bundle = pendingImport;
        pendingImport = null;
        if (bundle != null) bundle.wipe();
    }

    private static void wipeAll(char[]... values) {
        for (char[] value : values) CryptoEngine.wipe(value);
    }

    private void clearTrackedSensitiveViews() {
        clearPasswordInput(exportVaultPassphraseInput);
        exportVaultPassphraseInput = null;
        clearPasswordInput(exportBackupPassphraseInput);
        exportBackupPassphraseInput = null;
        clearPasswordInput(exportConfirmationPassphraseInput);
        exportConfirmationPassphraseInput = null;
        if (exportResultText != null) Ui.clear(exportResultText);
        exportResultText = null;
        if (importText != null) Ui.clear(importText);
        importText = null;
        clearPasswordInput(importDialogPassphraseInput);
        importDialogPassphraseInput = null;
        if (importPassphraseDialog != null && importPassphraseDialog.isShowing()) {
            importPassphraseDialog.dismiss();
        }
        importPassphraseDialog = null;
    }

    private static void clearPasswordInput(PasswordInput input) {
        if (input != null) Ui.clear(input.editText());
    }

    /**
     * The result stays on screen so the user can inspect it, but exporting to the
     * clipboard must go through the dedicated button that marks the clip sensitive.
     */
    private static final class SensitiveBackupResultEditText extends EditText {
        SensitiveBackupResultEditText(Context context) {
            super(context);
            SensitiveViewProtection.configure(this);
            setSaveEnabled(false);
            setTextIsSelectable(false);
            setLongClickable(false);
            setFocusable(false);
            setCursorVisible(false);
        }

        @Override
        public boolean onTextContextMenuItem(int id) {
            // Treat every context operation as handled without performing it. In
            // particular, this prevents an unlabelled system Copy clip.
            return true;
        }

        @Override
        public boolean onKeyShortcut(int keyCode, KeyEvent event) {
            if ((event.isCtrlPressed() || event.isMetaPressed())
                    && (keyCode == KeyEvent.KEYCODE_C || keyCode == KeyEvent.KEYCODE_X)) {
                return true;
            }
            return super.onKeyShortcut(keyCode, event);
        }

        @Override
        public boolean performAccessibilityAction(int action, Bundle arguments) {
            if (action == AccessibilityNodeInfo.ACTION_COPY
                    || action == AccessibilityNodeInfo.ACTION_CUT
                    || action == AccessibilityNodeInfo.ACTION_PASTE
                    || action == AccessibilityNodeInfo.ACTION_SET_TEXT) {
                return true;
            }
            return super.performAccessibilityAction(action, arguments);
        }

        @Override
        public void onProvideStructure(ViewStructure structure) {
            SensitiveViewProtection.redactStructure(structure);
        }

        @Override
        public void onProvideAutofillStructure(ViewStructure structure, int flags) {
            SensitiveViewProtection.redactStructure(structure);
        }

        @Override
        public void onProvideContentCaptureStructure(ViewStructure structure, int flags) {
            SensitiveViewProtection.redactStructure(structure);
        }
    }

    @Override
    protected void onSecureForegroundLost() {
        // Workers retain ownership of their local arrays until their finally blocks. Finishing
        // first causes every posted result to be rejected and wiped without touching live input.
        finish();
        busy = false;
        wipePendingImport();
        clearTrackedSensitiveViews();
    }

    @Override
    protected void onDestroy() {
        wipePendingImport();
        clearTrackedSensitiveViews();
        super.onDestroy();
    }
}
