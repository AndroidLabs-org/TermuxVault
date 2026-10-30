package app.termuxvault.secure;

import android.annotation.SuppressLint;

import android.app.AlertDialog;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.util.UUID;

@SuppressLint("SetTextI18n")
public final class RunEntryActivity extends SecureActivity {
    static final String EXTRA_ENTRY_ID = "entry_id";
    private String entryId;
    private TextView status;
    private boolean started;
    private boolean gateHeld;
    private boolean transportOwnsGate;
    private boolean permissionDialogShowing;
    private final RunResultPresentation handoffResult = new RunResultPresentation();

    static Intent createIntent(Context context, String id) {
        return new Intent(context, RunEntryActivity.class).putExtra(EXTRA_ENTRY_ID, id);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        entryId = getIntent().getStringExtra(EXTRA_ENTRY_ID);
        try {
            UUID.fromString(entryId);
        } catch (Exception exception) {
            finish();
            return;
        }
        if (!RunInFlightGuard.tryAcquire(entryId)) {
            Toast.makeText(this, "This command is already being prepared.",
                    Toast.LENGTH_SHORT).show();
            finish();
            return;
        }
        gateHeld = true;
        LinearLayout page = Ui.page(this);
        page.setGravity(Gravity.CENTER);
        status = Ui.text(this, "Preparing protected command…", 17, Ui.MUTED);
        status.setGravity(Gravity.CENTER);
        page.addView(status, Ui.matchWrap());
        setContentView(page);
        NotificationManager notifications = getSystemService(NotificationManager.class);
        notifications.cancel(NotificationIdentity.automationTag(entryId),
                NotificationIdentity.TAGGED_NOTIFICATION_ID);
        // One-release migration for a request notification posted by 1.0.13 or earlier.
        notifications.cancel(NotificationIdentity.legacyNumericId(entryId));
        begin();
    }

    private void begin() {
        if (started || !gateHeld) return;
        if (!TermuxContract.hasRunPermission(this)) {
            status.setText("Termux permission required");
            if (!TermuxContract.wasRunPermissionRequested(this)) {
                TermuxContract.requestRunPermission(this);
            } else {
                showRunPermissionRecovery();
            }
            return;
        }
        started = true;
        VaultState state;
        TermuxIdentity identity;
        VaultState.Entry entry;
        try {
            state = new VaultStore(this).load();
            entry = state.findEntry(entryId);
            if (entry == null) throw new VaultException("Entry no longer exists");
            identity = TermuxIdentity.read(this);
        } catch (PackageManager.NameNotFoundException exception) {
            fail("Termux is not installed in this Android profile.");
            return;
        } catch (VaultException exception) {
            fail(exception.getMessage());
            return;
        }
        boolean trusted = identity.matches(state.trustedTermuxCertificates);
        boolean replacement = !state.trustedTermuxCertificates.isEmpty() && !trusted;
        if (trusted) authenticateAndRun();
        else IdentityApproval.show(this, identity, replacement,
                () -> approveIdentityThenRun(identity), this::cancelAndFinish);
    }

    private void authenticateAndRun() {
        UnlockCoordinator.unlock(this,
                UnlockCoordinator.entryReason(entryId, UnlockCoordinator.EntryAction.RUN),
                new UnlockCoordinator.Callback() {
            @Override
            public void onUnlocked(byte[] vmk, byte[] vaultFingerprint) {
                if (!gateHeld || isFinishing() || isDestroyed()) {
                    CryptoEngine.wipe(vmk);
                    CryptoEngine.wipe(vaultFingerprint);
                    return;
                }
                authorizeExistingAndRun(vmk, vaultFingerprint);
            }

            @Override
            public void onCancelled() {
                cancelAndFinish();
            }
        });
    }

    private void approveIdentityThenRun(TermuxIdentity approvedIdentity) {
        UnlockCoordinator.unlock(this, UnlockCoordinator.entryReason(
                        entryId, UnlockCoordinator.EntryAction.TRUST_AND_RUN),
                new UnlockCoordinator.Callback() {
                    @Override
                    public void onUnlocked(byte[] vmk, byte[] vaultFingerprint) {
                        if (!gateHeld || isFinishing() || isDestroyed()) {
                            CryptoEngine.wipe(vmk);
                            CryptoEngine.wipe(vaultFingerprint);
                            return;
                        }
                        AuthorizedRun[] authorized = {null};
                        try {
                            new VaultStore(RunEntryActivity.this).mutateIfUnchanged(
                                    vaultFingerprint, state -> {
                                TermuxIdentity currentIdentity;
                                try {
                                    currentIdentity = TermuxIdentity.read(RunEntryActivity.this);
                                } catch (PackageManager.NameNotFoundException exception) {
                                    throw new VaultException("Termux is no longer installed", exception);
                                }
                                if (!currentIdentity.certificateDigests.equals(
                                        approvedIdentity.certificateDigests)) {
                                    throw new VaultException(
                                            "Termux identity changed during authorization");
                                }
                                state.trustedTermuxCertificates.clear();
                                state.trustedTermuxCertificates.addAll(currentIdentity.certificateDigests);
                                authorized[0] = authorizeRunFromState(state, vmk);
                            });
                            launchAuthorizedRun(authorized[0]);
                            authorized[0] = null;
                        } catch (Exception exception) {
                            if (authorized[0] != null) authorized[0].wipe();
                            fail("Termux trust could not be saved.");
                        } finally {
                            CryptoEngine.wipe(vmk);
                            CryptoEngine.wipe(vaultFingerprint);
                        }
                    }

                    @Override
                    public void onCancelled() {
                        cancelAndFinish();
                    }
                });
    }

    private void authorizeExistingAndRun(byte[] vmk, byte[] vaultFingerprint) {
        if (!gateHeld || isFinishing() || isDestroyed()) {
            CryptoEngine.wipe(vmk);
            CryptoEngine.wipe(vaultFingerprint);
            return;
        }
        AuthorizedRun authorized = null;
        try {
            authorized = new VaultStore(this).readIfUnchanged(
                    vaultFingerprint, state -> authorizeRunFromState(state, vmk));
        } catch (VaultException exception) {
            fail("The protected command could not be authorized.");
            return;
        } finally {
            CryptoEngine.wipe(vmk);
            CryptoEngine.wipe(vaultFingerprint);
        }
        launchAuthorizedRun(authorized);
    }

    private AuthorizedRun authorizeRunFromState(VaultState state, byte[] vmk)
            throws VaultException {
        VaultState.Entry entry = state.findEntry(entryId);
        if (entry == null) throw new VaultException("Entry no longer exists");
        TermuxIdentity currentIdentity;
        try {
            currentIdentity = TermuxIdentity.read(this);
        } catch (PackageManager.NameNotFoundException exception) {
            throw new VaultException("Termux is no longer installed", exception);
        }
        if (!currentIdentity.matches(state.trustedTermuxCertificates)) {
            throw new VaultException("Termux identity changed during authorization");
        }
        return new AuthorizedRun(VaultService.decryptEntry(vmk, entry),
                TextPolicy.safeDisplayTitle(entry.title),
                entry.pauseAfterRun, entry.notifyWhenFinished, entry.hideTerminalOutput);
    }

    private void launchAuthorizedRun(AuthorizedRun authorized) {
        if (authorized == null) {
            fail("The protected command could not be authorized.");
            return;
        }
        if (!gateHeld || isFinishing() || isDestroyed()) {
            authorized.wipe();
            return;
        }
        boolean notifyWhenFinished = authorized.notifyWhenFinished;
        CompletionStore.Request completion = null;
        if (notifyWhenFinished && !NotificationAccess.canPostCompletion(this)) {
            notifyWhenFinished = false;
            Toast.makeText(this,
                    "Completion notifications are blocked; the command will run without one.",
                    Toast.LENGTH_LONG).show();
        }
        if (notifyWhenFinished) {
            try {
                completion = CompletionStore.prepare(this, authorized.title);
            } catch (VaultException exception) {
                authorized.wipe();
                fail("The completion notification could not be prepared.");
                return;
            }
        }
        status.setText("Securely handing off to Termux…");
        byte[] handoff = authorized.command;
        authorized.command = null;
        // From this point the short-lived transport, not the Activity lifecycle, owns the guard.
        // A CLEAR_TOP recreation or Back press must not permit a second request while the first
        // listener and accepted Termux service request are still alive.
        transportOwnsGate = true;
        TermuxTransport.launch(this, authorized.title, handoff, authorized.pauseAfterRun,
                authorized.hideTerminalOutput, completion,
                new TermuxTransport.Callback() {
                    @Override
                    public void onHandoffComplete() {
                        transportOwnsGate = false;
                        handoffResult.clear();
                        releaseGate();
                        if (isFinishing() || isDestroyed()) return;
                        finish();
                    }

                    @Override
                    public void onHandoffFailed(String message, boolean offerTermuxAppInfo) {
                        handleHandoffFailure(message, offerTermuxAppInfo);
                    }
                });
    }

    private static final class AuthorizedRun {
        byte[] command;
        final String title;
        final boolean pauseAfterRun;
        final boolean notifyWhenFinished;
        final boolean hideTerminalOutput;

        AuthorizedRun(byte[] command, String title, boolean pauseAfterRun,
                      boolean notifyWhenFinished, boolean hideTerminalOutput) {
            this.command = command;
            this.title = title;
            this.pauseAfterRun = pauseAfterRun;
            this.notifyWhenFinished = notifyWhenFinished;
            this.hideTerminalOutput = hideTerminalOutput;
        }

        void wipe() {
            CryptoEngine.wipe(command);
            command = null;
        }
    }

    private void fail(String message) {
        fail(message, false);
    }

    private void fail(String message, boolean offerTermuxAppInfo) {
        releaseGate();
        showFailure(message, offerTermuxAppInfo);
    }

    private void handleHandoffFailure(String message, boolean offerTermuxAppInfo) {
        transportOwnsGate = false;
        releaseGate();
        if (isFinishing() || isDestroyed()) return;
        RunResultPresentation.Failure immediate =
                handoffResult.failed(message, offerTermuxAppInfo);
        if (immediate != null) {
            showFailure(immediate.message, immediate.offerTermuxAppInfo);
        }
    }

    private void showFailure(String message, boolean offerTermuxAppInfo) {
        if (isFinishing() || isDestroyed()) return;
        AlertDialog.Builder builder = new AlertDialog.Builder(this)
                .setTitle("Command not run")
                .setMessage(message)
                .setOnCancelListener(dialog -> finish());
        if (offerTermuxAppInfo) {
            builder.setPositiveButton("Open Termux app info", (dialog, which) -> {
                NotificationAccess.openTermuxAppDetails(this);
                finish();
            }).setNegativeButton("Close", (dialog, which) -> finish());
        } else {
            builder.setPositiveButton("Close", (dialog, which) -> finish());
        }
        Ui.showSecure(builder);
    }

    @Override
    protected void onResume() {
        super.onResume();
        RunResultPresentation.Failure pending = handoffResult.resume();
        if (pending != null) showFailure(pending.message, pending.offerTermuxAppInfo);
    }

    @Override
    protected void onPause() {
        handoffResult.pause();
        super.onPause();
    }

    private void showRunPermissionRecovery() {
        if (permissionDialogShowing || !gateHeld || isFinishing() || isDestroyed()) return;
        permissionDialogShowing = true;
        boolean canRequestAgain = TermuxContract.shouldShowRunPermissionRationale(this);
        AlertDialog.Builder builder = new AlertDialog.Builder(this)
                .setTitle("Termux permission required")
                .setMessage(canRequestAgain
                        ? "Run commands in Termux environment was denied. Request it again, or "
                                + "open App info → Permissions and allow it manually."
                        : "Open App info → Permissions and allow Run commands in Termux "
                                + "environment, then run the command again.")
                .setNegativeButton("Cancel", (dialog, which) -> cancelAndFinish())
                .setOnCancelListener(dialog -> cancelAndFinish());
        if (canRequestAgain) {
            builder.setPositiveButton("Request again", (dialog, which) -> {
                permissionDialogShowing = false;
                TermuxContract.requestRunPermission(this);
            });
            builder.setNeutralButton("App settings", (dialog, which) -> openAppSettingsAndFinish());
        } else {
            builder.setPositiveButton("Open app settings",
                    (dialog, which) -> openAppSettingsAndFinish());
        }
        Ui.showSecure(builder);
    }

    private void openAppSettingsAndFinish() {
        permissionDialogShowing = false;
        NotificationAccess.openAppDetails(this);
        cancelAndFinish();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != TermuxContract.PERMISSION_REQUEST_CODE) return;
        if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) begin();
        else showRunPermissionRecovery();
    }

    private void cancelAndFinish() {
        releaseGate();
        finish();
    }

    private void releaseGate() {
        if (!gateHeld) return;
        gateHeld = false;
        RunInFlightGuard.release(entryId);
    }

    @Override
    protected void onSecureForegroundLost() {
        if (transportOwnsGate || handoffResult.hasPendingFailure()) {
            // Authorization is complete and the Activity no longer owns decrypted command or key
            // material. Keep only this stopped result screen so a fixed, non-sensitive transport
            // failure can be presented once when the user returns from Termux.
            return;
        }
        cancelAndFinish();
    }

    @Override
    protected void onDestroy() {
        if (!transportOwnsGate) releaseGate();
        super.onDestroy();
    }
}
