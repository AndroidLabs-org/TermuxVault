package app.termuxvault.secure;

import android.annotation.SuppressLint;

import android.Manifest;
import android.app.AlertDialog;
import android.app.NotificationManager;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.DragEvent;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

@SuppressLint("SetTextI18n")
public final class MainActivity extends SecureActivity {
    private static final int NOTIFICATION_REQUEST_CODE = 2402;
    private static final String EXTRA_OPEN_BIOMETRIC_SETTINGS =
            "app.termuxvault.secure.extra.OPEN_BIOMETRIC_SETTINGS";
    private final List<VaultState.Entry> entries = new ArrayList<>();
    private EntryAdapter adapter;
    private TextView identityStatus;
    private TextView emptyState;
    private Button identityButton;
    private Button untrustButton;
    private ListView commandList;
    private String draggedEntryId;
    private boolean dragDropped;
    private boolean orderSaveInProgress;
    private AlertDialog termuxSetupDialog;
    private int initialPermissionRequestInFlight;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (!new VaultStore(this).exists()) {
            openSetupAndFinish();
            return;
        }
        buildUi();
    }

    @Override
    protected void onResume() {
        super.onResume();
        VaultStore store = new VaultStore(this);
        if (!store.exists()) {
            openSetupAndFinish();
            return;
        }
        if (adapter == null) return;
        if (getIntent().getBooleanExtra(EXTRA_OPEN_BIOMETRIC_SETTINGS, false)) {
            getIntent().removeExtra(EXTRA_OPEN_BIOMETRIC_SETTINGS);
            if (BiometricAvailability.openSettings(this)) return;
        }
        reload();
        advanceInitialPermissionFlow();
    }

    static Intent afterSetupBiometricSettingsIntent(Context context) {
        return new Intent(context, MainActivity.class)
                .putExtra(EXTRA_OPEN_BIOMETRIC_SETTINGS, true)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
    }

    private boolean offerTermuxSetupGuideIfPending() {
        if (!TermuxSetupOnboarding.isPending(this)) return false;
        if (termuxSetupDialog != null) return true;

        AlertDialog dialog = Ui.createSecure(new AlertDialog.Builder(this)
                .setTitle("Prepare Termux")
                .setMessage("Termux needs a one-time setup before Termux Vault can run commands. "
                        + "Would you like to open the setup guide in the FAQ now?\n\n"
                        + "You can find it later under Settings → FAQ.")
                .setPositiveButton("Open setup guide", (ignored, which) ->
                        completeTermuxSetupOffer(true))
                .setNegativeButton("Not now", (ignored, which) ->
                        completeTermuxSetupOffer(false))
                .setOnCancelListener(ignored -> completeTermuxSetupOffer(false)));
        dialog.setOnDismissListener(ignored -> {
            if (termuxSetupDialog == dialog) termuxSetupDialog = null;
        });
        termuxSetupDialog = dialog;
        dialog.show();
        return true;
    }

    private void completeTermuxSetupOffer(boolean openGuide) {
        if (!TermuxSetupOnboarding.markComplete(this)) {
            Ui.showError(this, "Your setup-guide choice could not be saved. The offer will appear "
                    + "again the next time Termux Vault opens.");
            return;
        }
        if (openGuide) {
            startActivity(AboutActivity.prepareTermuxIntent(this));
        }
    }

    private void openSetupAndFinish() {
        if (isFinishing() || isDestroyed()) return;
        startActivity(new Intent(this, SetupActivity.class));
        finish();
    }

    private void buildUi() {
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Ui.BACKGROUND);
        LinearLayout page = Ui.page(this);
        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        TextView title = Ui.title(this, "Termux Vault");
        header.addView(title, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        Button settings = Ui.button(this, "Settings");
        settings.setOnClickListener(view -> startActivity(new Intent(this, SettingsActivity.class)));
        header.addView(settings);
        page.addView(header, Ui.matchWrap());
        Ui.addSpace(page, 8);

        LinearLayout identityPanel = new LinearLayout(this);
        identityPanel.setOrientation(LinearLayout.VERTICAL);
        identityPanel.setBackgroundResource(R.drawable.panel_background);
        identityPanel.setPadding(Ui.dp(this, 12), Ui.dp(this, 10),
                Ui.dp(this, 12), Ui.dp(this, 10));
        TextView identityHeading = Ui.text(this, "Termux identity", 14, Ui.TEXT);
        identityHeading.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        identityPanel.addView(identityHeading, Ui.matchWrap());
        Ui.addSpace(identityPanel, 4);
        identityStatus = Ui.text(this, "Checking Termux…", 13, Ui.MUTED);
        identityPanel.addView(identityStatus, Ui.matchWrap());
        Ui.addSpace(identityPanel, 8);
        LinearLayout identityActions = new LinearLayout(this);
        identityActions.setGravity(Gravity.END | Gravity.CENTER_VERTICAL);
        identityButton = Ui.button(this, "Verify");
        identityButton.setOnClickListener(view -> authenticateIdentityUpdate());
        identityActions.addView(identityButton);
        untrustButton = Ui.button(this, "Untrust");
        untrustButton.setVisibility(View.GONE);
        untrustButton.setOnClickListener(view -> confirmUntrust());
        LinearLayout.LayoutParams untrustParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        untrustParams.setMarginStart(Ui.dp(this, 6));
        identityActions.addView(untrustButton, untrustParams);
        identityPanel.addView(identityActions, Ui.matchWrap());
        page.addView(identityPanel, Ui.matchWrap());
        Ui.addSpace(page, 10);

        emptyState = Ui.text(this, "Add a protected command to begin.", 15, Ui.MUTED);
        page.addView(emptyState, Ui.matchWrap());
        commandList = new ListView(this);
        commandList.setDividerHeight(0);
        commandList.setCacheColorHint(Ui.BACKGROUND);
        commandList.setVerticalScrollBarEnabled(true);
        commandList.setClipToPadding(false);
        commandList.setPadding(0, 0, 0, Ui.dp(this, 72));
        adapter = new EntryAdapter();
        commandList.setAdapter(adapter);
        commandList.setOnItemClickListener((parent, view, position, id) -> run(entries.get(position).id));
        commandList.setOnItemLongClickListener((parent, view, position, id) -> {
            showEntryActions(entries.get(position));
            return true;
        });
        commandList.setOnDragListener(this::handleEntryDrag);
        page.addView(commandList, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        root.addView(page, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        Button add = Ui.button(this, "+");
        add.setTextSize(26);
        add.setTextColor(Ui.BACKGROUND);
        add.setGravity(Gravity.CENTER);
        add.setPadding(0, 0, 0, 0);
        add.setMinWidth(0);
        add.setMinHeight(0);
        add.setContentDescription("Add protected command");
        add.setBackgroundResource(R.drawable.floating_button_background);
        add.setOnClickListener(view -> startActivity(EntryActivity.createIntent(this, null)));
        FrameLayout.LayoutParams addParams = new FrameLayout.LayoutParams(
                Ui.dp(this, 56), Ui.dp(this, 56), Gravity.END | Gravity.BOTTOM);
        addParams.setMargins(Ui.dp(this, 20), Ui.dp(this, 20),
                Ui.dp(this, 20), Ui.dp(this, 20));
        root.addView(add, addParams);
        setContentView(root);
    }

    private void reload() {
        try {
            VaultState state = new VaultStore(this).load();
            entries.clear();
            entries.addAll(state.entries);
            adapter.notifyDataSetChanged();
            emptyState.setVisibility(entries.isEmpty() ? View.VISIBLE : View.GONE);
            updateIdentityStatus(state);
        } catch (VaultException exception) {
            Ui.showError(this, exception.getMessage());
        }
    }

    private void updateIdentityStatus(VaultState state) {
        try {
            TermuxIdentity identity = TermuxIdentity.read(this);
            if (state.trustedTermuxCertificates.isEmpty()) {
                identityStatus.setText("Termux installed — identity not trusted yet");
                identityStatus.setTextColor(Ui.MUTED);
                identityButton.setText("Trust");
                untrustButton.setVisibility(View.GONE);
            } else if (identity.matches(state.trustedTermuxCertificates)) {
                identityStatus.setText("Termux identity verified");
                identityStatus.setTextColor(Ui.ACCENT);
                identityButton.setText("Details");
                untrustButton.setVisibility(View.VISIBLE);
            } else {
                identityStatus.setText("Termux identity changed — execution blocked");
                identityStatus.setTextColor(Ui.DANGER);
                identityButton.setText("Review");
                untrustButton.setVisibility(View.VISIBLE);
            }
        } catch (PackageManager.NameNotFoundException exception) {
            identityStatus.setText("Termux is not installed in this Android profile");
            identityStatus.setTextColor(Ui.DANGER);
            identityButton.setText("Retry");
            untrustButton.setVisibility(state.trustedTermuxCertificates.isEmpty()
                    ? View.GONE : View.VISIBLE);
        } catch (VaultException exception) {
            identityStatus.setText("Termux identity could not be verified");
            identityStatus.setTextColor(Ui.DANGER);
            identityButton.setText("Retry");
            untrustButton.setVisibility(state.trustedTermuxCertificates.isEmpty()
                    ? View.GONE : View.VISIBLE);
        }
    }

    private void confirmUntrust() {
        Ui.showSecure(new AlertDialog.Builder(this)
                .setTitle("Untrust Termux?")
                .setMessage("Protected commands will be blocked until a Termux installation is trusted again.")
                .setPositiveButton("Untrust", (dialog, which) -> UnlockCoordinator.unlock(
                        this, AuthorizationReason.untrustTermux(),
                        new UnlockCoordinator.Callback() {
                            @Override
                            public void onUnlocked(byte[] vmk, byte[] vaultFingerprint) {
                                CryptoEngine.wipe(vmk);
                                try {
                                    new VaultStore(MainActivity.this).mutateIfUnchanged(
                                            vaultFingerprint, state ->
                                            state.trustedTermuxCertificates.clear());
                                    reload();
                                } catch (VaultException exception) {
                                    Ui.showError(MainActivity.this, "Termux trust could not be removed.");
                                } finally {
                                    CryptoEngine.wipe(vaultFingerprint);
                                }
                            }

                            @Override
                            public void onCancelled() {
                            }
                        }))
                .setNegativeButton("Cancel", null));
    }

    private void authenticateIdentityUpdate() {
        VaultState state;
        TermuxIdentity identity;
        try {
            state = new VaultStore(this).load();
            identity = TermuxIdentity.read(this);
        } catch (PackageManager.NameNotFoundException exception) {
            Ui.showError(this, "Install Termux in this Android profile first.");
            return;
        } catch (VaultException exception) {
            Ui.showError(this, exception.getMessage());
            return;
        }
        boolean alreadyTrusted = identity.matches(state.trustedTermuxCertificates);
        if (alreadyTrusted) {
            Ui.showSecure(new AlertDialog.Builder(this)
                    .setTitle("Verified Termux identity")
                    .setMessage(identity.displayDetails())
                    .setPositiveButton("OK", null));
            return;
        }
        boolean replacement = !state.trustedTermuxCertificates.isEmpty();
        IdentityApproval.show(this, identity, replacement, () -> UnlockCoordinator.unlock(
                this, UnlockCoordinator.termuxTrustReason(),
                new UnlockCoordinator.Callback() {
                    @Override
                    public void onUnlocked(byte[] vmk, byte[] vaultFingerprint) {
                        CryptoEngine.wipe(vmk);
                        try {
                            trust(identity, vaultFingerprint);
                            reload();
                        } catch (VaultException exception) {
                            Ui.showError(MainActivity.this, "Termux trust could not be saved.");
                        } finally {
                            CryptoEngine.wipe(vaultFingerprint);
                        }
                    }

                    @Override
                    public void onCancelled() {
                    }
                }), () -> { });
    }

    private void trust(TermuxIdentity identity, byte[] vaultFingerprint) throws VaultException {
        new VaultStore(this).mutateIfUnchanged(vaultFingerprint, state -> {
            TermuxIdentity current;
            try {
                current = TermuxIdentity.read(this);
            } catch (PackageManager.NameNotFoundException exception) {
                throw new VaultException("Termux is no longer installed", exception);
            }
            if (!current.certificateDigests.equals(identity.certificateDigests)) {
                throw new VaultException("Termux identity changed during authorization");
            }
            state.trustedTermuxCertificates.clear();
            state.trustedTermuxCertificates.addAll(current.certificateDigests);
        });
    }

    private void showEntryActions(VaultState.Entry entry) {
        String[] actions = {"Run", "Edit", "Delete", "Tasker ID"};
        Ui.showSecure(new AlertDialog.Builder(this)
                .setTitle(TextPolicy.safeDisplayTitle(entry.title))
                .setItems(actions, (dialog, which) -> {
                    if (which == 0) run(entry.id);
                    else if (which == 1) startActivity(EntryActivity.createIntent(this, entry.id));
                    else if (which == 2) confirmDelete(entry);
                    else showAutomationId(entry);
                }));
    }

    private void confirmDelete(VaultState.Entry entry) {
        Ui.showSecure(new AlertDialog.Builder(this)
                .setTitle("Delete protected command?")
                .setMessage("Command: " + TextPolicy.safeDisplayTitle(entry.title)
                        + "\n\nThis removes the encrypted command from the active vault.")
                .setPositiveButton("Delete", (dialog, which) -> UnlockCoordinator.unlock(
                        this, UnlockCoordinator.entryReason(
                                entry.id, UnlockCoordinator.EntryAction.DELETE),
                        new UnlockCoordinator.Callback() {
                            @Override
                            public void onUnlocked(byte[] vmk, byte[] vaultFingerprint) {
                                CryptoEngine.wipe(vmk);
                                try {
                                    new VaultStore(MainActivity.this).mutateIfUnchanged(
                                            vaultFingerprint, state -> {
                                        VaultState.Entry current = state.findEntry(entry.id);
                                        if (current == null) throw new VaultException("Entry no longer exists");
                                        state.entries.remove(current);
                                    });
                                    CommandWidgetProvider.refreshAll(MainActivity.this);
                                    reload();
                                } catch (VaultException exception) {
                                    Ui.showError(MainActivity.this, exception.getMessage());
                                } finally {
                                    CryptoEngine.wipe(vaultFingerprint);
                                }
                            }

                            @Override
                            public void onCancelled() {
                            }
                        }))
                .setNegativeButton("Cancel", null));
    }

    private void showAutomationId(VaultState.Entry entry) {
        String packageName = getPackageName();
        String action = AutomationContract.action(packageName);
        String extra = AutomationContract.extra(entry.id);

        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(Ui.dp(this, 8), Ui.dp(this, 4),
                Ui.dp(this, 8), Ui.dp(this, 4));
        TextView instructions = Ui.text(this,
                "In Tasker, add a Send Intent action. Copy each value below into the matching "
                        + "field, then set Target to " + AutomationContract.TARGET + ".",
                13, Ui.MUTED);
        instructions.setLineSpacing(0, 1.05f);
        body.addView(instructions, Ui.matchWrap());
        Ui.addSpace(body, 12);
        addTaskerField(body, "Action", action);
        addTaskerField(body, "Package", packageName);
        addTaskerField(body, "Extra", extra);
        TextView note = Ui.text(this,
                "This posts an authentication notification; it does not run unattended.",
                12, Ui.MUTED);
        note.setLineSpacing(0, 1.05f);
        body.addView(note, Ui.matchWrap());

        ScrollView scroll = new ScrollView(this);
        scroll.addView(body);
        AlertDialog dialog = Ui.createSecure(new AlertDialog.Builder(this)
                .setTitle("Tasker fields")
                .setView(scroll)
                .setPositiveButton("Copy all", null)
                .setNegativeButton("Close", null));
        dialog.setOnShowListener(ignored -> {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(view ->
                    copyTaskerValue("Termux Vault Tasker fields",
                            AutomationContract.copyAll(packageName, entry.id),
                            "All Tasker fields copied"));
            int available = getResources().getDisplayMetrics().widthPixels - Ui.dp(this, 32);
            dialog.getWindow().setLayout(Math.min(available, Ui.dp(this, 560)),
                    ViewGroup.LayoutParams.WRAP_CONTENT);
        });
        dialog.show();
    }

    private void addTaskerField(LinearLayout body, String label, String value) {
        TextView heading = Ui.text(this, label, 13, Ui.TEXT);
        heading.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        body.addView(heading, Ui.matchWrap());

        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        TextView field = Ui.text(this, value, 12, Ui.MUTED);
        field.setTypeface(Typeface.MONOSPACE);
        field.setLineSpacing(0, 1.02f);
        row.addView(field, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        Button copy = Ui.button(this, "Copy");
        copy.setTextSize(12);
        copy.setOnClickListener(view ->
                copyTaskerValue("Termux Vault Tasker " + label, value, label + " copied"));
        LinearLayout.LayoutParams copyParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        copyParams.setMarginStart(Ui.dp(this, 8));
        row.addView(copy, copyParams);
        body.addView(row, Ui.matchWrap());
        Ui.addSpace(body, 10);
    }

    private void copyTaskerValue(String clipboardLabel, String value, String confirmation) {
        try {
            ClipboardManager clipboard = getSystemService(ClipboardManager.class);
            if (clipboard == null) throw new IllegalStateException("Clipboard unavailable");
            clipboard.setPrimaryClip(ClipData.newPlainText(clipboardLabel, value));
            Toast.makeText(this, confirmation, Toast.LENGTH_SHORT).show();
        } catch (RuntimeException exception) {
            Toast.makeText(this, "Android could not copy this field", Toast.LENGTH_SHORT).show();
        }
    }

    private void run(String id) {
        startActivity(RunEntryActivity.createIntent(this, id));
    }

    private boolean handleEntryDrag(View ignored, DragEvent event) {
        Object localState = event.getLocalState();
        if (!(localState instanceof String entryId)) return false;
        switch (event.getAction()) {
            case DragEvent.ACTION_DRAG_STARTED:
                if (orderSaveInProgress || findEntryPosition(entryId) < 0) return false;
                draggedEntryId = entryId;
                dragDropped = false;
                return true;
            case DragEvent.ACTION_DRAG_LOCATION:
                if (!entryId.equals(draggedEntryId)) return false;
                moveDraggedEntry((int) event.getX(), (int) event.getY());
                autoScrollDuringDrag(event.getY());
                return true;
            case DragEvent.ACTION_DROP:
                if (!entryId.equals(draggedEntryId)) return false;
                dragDropped = true;
                saveEntryOrder();
                return true;
            case DragEvent.ACTION_DRAG_ENDED:
                if (!dragDropped) reload();
                draggedEntryId = null;
                dragDropped = false;
                return true;
            default:
                return true;
        }
    }

    private int findEntryPosition(String entryId) {
        for (int i = 0; i < entries.size(); i++) {
            if (entryId.equals(entries.get(i).id)) return i;
        }
        return -1;
    }

    private void moveDraggedEntry(int x, int y) {
        int from = findEntryPosition(draggedEntryId);
        if (from < 0 || entries.size() < 2) return;
        int target = commandList.pointToPosition(x, y);
        if (target == ListView.INVALID_POSITION) {
            if (y < 0) target = 0;
            else if (y > commandList.getHeight()) target = entries.size() - 1;
            else return;
        }
        if (target == from) return;
        VaultState.Entry moved = entries.remove(from);
        entries.add(Math.max(0, Math.min(target, entries.size())), moved);
        adapter.notifyDataSetChanged();
    }

    private void autoScrollDuringDrag(float y) {
        int edge = Ui.dp(this, 56);
        if (y < edge) commandList.scrollListBy(-Ui.dp(this, 18));
        else if (y > commandList.getHeight() - edge) commandList.scrollListBy(Ui.dp(this, 18));
    }

    private void saveEntryOrder() {
        orderSaveInProgress = true;
        List<String> order = new ArrayList<>();
        for (VaultState.Entry entry : entries) order.add(entry.id);
        new Thread(() -> {
            VaultException failure = null;
            try {
                new VaultStore(MainActivity.this).mutate(state -> {
                    if (state.entries.size() != order.size()) {
                        throw new VaultException("Command list changed during reordering");
                    }
                    List<VaultState.Entry> reordered = new ArrayList<>();
                    for (String id : order) {
                        VaultState.Entry current = state.findEntry(id);
                        if (current == null || reordered.contains(current)) {
                            throw new VaultException("Command list changed during reordering");
                        }
                        reordered.add(current);
                    }
                    state.entries.clear();
                    state.entries.addAll(reordered);
                });
            } catch (VaultException exception) {
                failure = exception;
            }
            VaultException finalFailure = failure;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                orderSaveInProgress = false;
                reload();
                if (finalFailure != null) Ui.showError(MainActivity.this,
                        "Command order could not be saved.");
            });
        }, "vault-reorder").start();
    }

    private void advanceInitialPermissionFlow() {
        if (!isSecureSessionActive()) return;
        boolean notificationRequestNeeded = shouldRequestNotificationPermission();
        boolean termuxRequestNeeded = !notificationRequestNeeded
                && shouldRequestTermuxPermission();
        InitialPermissionFlow.Step next = InitialPermissionFlow.next(
                TermuxSetupOnboarding.isPending(this),
                initialPermissionRequestInFlight != 0,
                notificationRequestNeeded,
                termuxRequestNeeded);
        switch (next) {
            case WAIT, COMPLETE:
                return;
            case REQUEST_NOTIFICATIONS:
                if (android.os.Build.VERSION.SDK_INT < 33) {
                    getWindow().getDecorView().post(this::advanceInitialPermissionFlow);
                    return;
                }
                getPreferences(MODE_PRIVATE).edit()
                        .putBoolean("asked_notifications", true).apply();
                requestInitialPermission(
                        new String[]{Manifest.permission.POST_NOTIFICATIONS},
                        NOTIFICATION_REQUEST_CODE);
                return;
            case REQUEST_TERMUX:
                getPreferences(MODE_PRIVATE).edit().putBoolean("asked_termux", true).apply();
                initialPermissionRequestInFlight = TermuxContract.PERMISSION_REQUEST_CODE;
                try {
                    TermuxContract.requestRunPermission(this);
                } catch (RuntimeException ignored) {
                    initialPermissionRequestInFlight = 0;
                    getWindow().getDecorView().post(this::advanceInitialPermissionFlow);
                }
                return;
            case OFFER_SETUP_GUIDE:
                offerTermuxSetupGuideIfPending();
        }
    }

    private boolean shouldRequestNotificationPermission() {
        return android.os.Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
                && !getPreferences(MODE_PRIVATE).getBoolean("asked_notifications", false);
    }

    private boolean shouldRequestTermuxPermission() {
        if (TermuxContract.hasRunPermission(this)) return false;
        try {
            getPackageManager().getPackageInfo(TermuxIdentity.PACKAGE_NAME, 0);
            boolean legacyAsked = getPreferences(MODE_PRIVATE)
                    .getBoolean("asked_termux", false);
            if (legacyAsked && !TermuxContract.wasRunPermissionRequested(this)) {
                // Preserve the one-request limit for users upgrading from the original
                // Activity-local permission tracking.
                TermuxContract.markRunPermissionRequested(this);
            }
            return !TermuxContract.wasRunPermissionRequested(this);
        } catch (PackageManager.NameNotFoundException ignored) {
            return false;
        }
    }

    private void requestInitialPermission(String[] permissions, int requestCode) {
        initialPermissionRequestInFlight = requestCode;
        try {
            requestPermissions(permissions, requestCode);
        } catch (RuntimeException ignored) {
            initialPermissionRequestInFlight = 0;
            getWindow().getDecorView().post(this::advanceInitialPermissionFlow);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != NOTIFICATION_REQUEST_CODE
                && requestCode != TermuxContract.PERMISSION_REQUEST_CODE) return;
        if (initialPermissionRequestInFlight != 0
                && initialPermissionRequestInFlight != requestCode) return;
        initialPermissionRequestInFlight = 0;
        advanceInitialPermissionFlow();
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
            return entries.get(position).id.hashCode();
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            LinearLayout row = new LinearLayout(MainActivity.this);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(Ui.dp(MainActivity.this, 10), Ui.dp(MainActivity.this, 12),
                    Ui.dp(MainActivity.this, 10), Ui.dp(MainActivity.this, 12));
            TextView icon = Ui.text(MainActivity.this, EntryIcons.glyph(getItem(position).icon), 20, Ui.ACCENT);
            icon.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
            icon.setGravity(Gravity.CENTER);
            row.addView(icon, new LinearLayout.LayoutParams(Ui.dp(MainActivity.this, 50),
                    ViewGroup.LayoutParams.MATCH_PARENT));
            String safeTitle = TextPolicy.safeDisplayTitle(getItem(position).title);
            TextView title = Ui.text(MainActivity.this, safeTitle, 17, Ui.TEXT);
            title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
            row.addView(title, new LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1));
            TextView drag = Ui.text(MainActivity.this, "≡", 28, Ui.MUTED);
            drag.setGravity(Gravity.CENTER);
            drag.setContentDescription("Drag to reorder " + safeTitle);
            drag.setTooltipText("Long-press and drag to reorder");
            drag.setPadding(Ui.dp(MainActivity.this, 10), 0,
                    Ui.dp(MainActivity.this, 10), 0);
            String entryId = getItem(position).id;
            drag.setOnClickListener(view -> { });
            drag.setOnLongClickListener(view -> view.startDragAndDrop(
                    ClipData.newPlainText("", ""), new View.DragShadowBuilder(view), entryId, 0));
            row.addView(drag, new LinearLayout.LayoutParams(
                    Ui.dp(MainActivity.this, 48), ViewGroup.LayoutParams.MATCH_PARENT));
            TextView arrow = Ui.text(MainActivity.this, "›", 28, Ui.MUTED);
            row.addView(arrow);
            return row;
        }
    }
}
