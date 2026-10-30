package app.termuxvault.secure;

import android.annotation.SuppressLint;
import android.app.AlertDialog;
import android.app.NotificationManager;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.os.Bundle;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.method.LinkMovementMethod;
import android.text.style.URLSpan;
import android.view.Gravity;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.security.GeneralSecurityException;
import java.util.Arrays;

@SuppressLint("SetTextI18n")
public final class SettingsActivity extends SecureActivity {
    private static final String PROJECT_URL = "https://github.com/AndroidLabs-org/TermuxVault";
    private enum BiometricUiState {
        CHECKING,
        ENABLED,
        ENABLED_WARNING,
        REVIEW_WARNING,
        DISABLED,
        RESET_INVALIDATED,
        RESET_UNAVAILABLE,
        VAULT_UNAVAILABLE
    }

    private static final class PolicyReviewState {
        final String iv;
        final String ciphertext;

        PolicyReviewState(String iv, String ciphertext) {
            this.iv = iv;
            this.ciphertext = ciphertext;
        }
    }

    private TextView biometricStatus;
    private Button biometricButton;
    private TextView notificationStatus;
    private TextView automationNotificationStatus;
    private TextView termuxPermissionStatus;
    private Button notificationChannelButton;
    private Button automationNotificationChannelButton;
    private BiometricUiState biometricUiState = BiometricUiState.CHECKING;
    private boolean biometricOperation;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView scroll = new ScrollView(this);
        LinearLayout page = Ui.page(this);
        scroll.addView(page);
        page.addView(Ui.title(this, "Settings"), Ui.matchWrap());
        addSettingsHeading(page, "Vault access");

        biometricStatus = Ui.text(this, "Biometric unlock: Checking…", 15, Ui.MUTED);
        page.addView(biometricStatus, Ui.matchWrap());
        Ui.addSpace(page, 4);
        page.addView(Ui.text(this, BiometricEnrollmentUi.REQUIREMENT, 14, Ui.MUTED),
                Ui.matchWrap());
        Ui.addSpace(page, 8);
        biometricButton = Ui.button(this, BiometricEnrollmentUi.ADD_ACTION);
        biometricButton.setOnClickListener(view -> {
            if (biometricOperation) return;
            if (biometricUiState == BiometricUiState.ENABLED
                    || biometricUiState == BiometricUiState.ENABLED_WARNING) {
                beginRemoveBiometric();
            } else if (biometricUiState == BiometricUiState.REVIEW_WARNING) {
                showBiometricPolicyReview();
            } else if (biometricUiState == BiometricUiState.RESET_INVALIDATED
                    || biometricUiState == BiometricUiState.RESET_UNAVAILABLE) {
                showBiometricReset();
            } else if (biometricUiState == BiometricUiState.DISABLED) {
                beginAddBiometric();
            }
        });
        page.addView(biometricButton, Ui.matchWrap());
        Ui.addSpace(page, 8);

        Button change = Ui.button(this, "Change vault passphrase");
        change.setOnClickListener(view -> showPassphraseChange());
        page.addView(change, Ui.matchWrap());
        Ui.addSpace(page, 20);

        addSettingsHeading(page, "Backups");
        page.addView(Ui.text(this,
                "Create a portable encrypted backup, or merge entries from a backup into this vault.",
                14, Ui.MUTED), Ui.matchWrap());
        Ui.addSpace(page, 8);
        Button encryptedExport = Ui.button(this, "Export encrypted backup");
        encryptedExport.setOnClickListener(view ->
                startActivity(BackupActivity.intent(this, BackupActivity.Mode.EXPORT_ENCRYPTED)));
        page.addView(encryptedExport, Ui.matchWrap());
        Ui.addSpace(page, 6);
        Button importBackup = Ui.button(this, "Import backup");
        importBackup.setOnClickListener(view ->
                startActivity(BackupActivity.intent(this, BackupActivity.Mode.IMPORT)));
        page.addView(importBackup, Ui.matchWrap());
        Ui.addSpace(page, 20);

        addSettingsHeading(page, "Android access");
        page.addView(Ui.text(this,
                "Android controls Vault's notification access and permission to run commands "
                        + "in Termux.",
                14, Ui.MUTED), Ui.matchWrap());
        Ui.addSpace(page, 12);

        addSubheading(page, "Notification channels");
        notificationStatus = Ui.text(this, "Completion notifications: Checking…", 15, Ui.MUTED);
        page.addView(notificationStatus, Ui.matchWrap());
        notificationChannelButton = Ui.button(this, "Open completion notification channel");
        notificationChannelButton.setOnClickListener(
                view -> NotificationAccess.openCompletionChannelSettings(this));
        notificationChannelButton.setVisibility(View.GONE);
        page.addView(notificationChannelButton, Ui.matchWrap());
        Ui.addSpace(page, 6);

        automationNotificationStatus = Ui.text(
                this, "Tasker authentication requests: Checking…", 15, Ui.MUTED);
        page.addView(automationNotificationStatus, Ui.matchWrap());
        automationNotificationChannelButton = Ui.button(
                this, "Open Tasker request notification channel");
        automationNotificationChannelButton.setOnClickListener(
                view -> NotificationAccess.openAutomationChannelSettings(this));
        automationNotificationChannelButton.setVisibility(View.GONE);
        page.addView(automationNotificationChannelButton, Ui.matchWrap());
        Ui.addSpace(page, 14);

        addSubheading(page, "App permissions");
        termuxPermissionStatus = Ui.text(this, "Run commands in Termux: Checking…", 15, Ui.MUTED);
        page.addView(termuxPermissionStatus, Ui.matchWrap());
        Ui.addSpace(page, 8);
        Button appSettingsButton = Ui.button(this, "Open Termux Vault app info");
        appSettingsButton.setOnClickListener(view -> NotificationAccess.openAppDetails(this));
        page.addView(appSettingsButton, Ui.matchWrap());
        Ui.addSpace(page, 14);

        addSubheading(page, "Termux compatibility");
        page.addView(Ui.text(this,
                "Use Termux App info to review Display over other apps when foreground opening "
                        + "is blocked on your Android variant.",
                14, Ui.MUTED), Ui.matchWrap());
        Ui.addSpace(page, 8);
        Button termuxSettingsButton = Ui.button(this, "Open Termux app info");
        termuxSettingsButton.setOnClickListener(
                view -> NotificationAccess.openTermuxAppDetails(this));
        page.addView(termuxSettingsButton, Ui.matchWrap());
        Ui.addSpace(page, 20);

        addSettingsHeading(page, "Danger zone");
        TextView dangerExplanation = Ui.text(this,
                "These actions expose plaintext secrets or permanently remove protected data.",
                14, Ui.DANGER);
        page.addView(dangerExplanation, Ui.matchWrap());
        Ui.addSpace(page, 8);
        Button plaintextExport = Ui.button(this, "Export unprotected readable backup");
        plaintextExport.setOnClickListener(view -> startActivity(
                BackupActivity.intent(this, BackupActivity.Mode.EXPORT_PLAINTEXT)));
        page.addView(plaintextExport, Ui.matchWrap());
        Ui.addSpace(page, 6);
        Button deleteEntries = Ui.button(this, "Delete all entries");
        deleteEntries.setOnClickListener(view -> showDestructiveDialog(false));
        page.addView(deleteEntries, Ui.matchWrap());
        Ui.addSpace(page, 6);
        Button resetVault = Ui.button(this, "Reset vault completely");
        resetVault.setOnClickListener(view -> showDestructiveDialog(true));
        page.addView(resetVault, Ui.matchWrap());
        Ui.addSpace(page, 20);

        addSettingsHeading(page, "Information");
        Button faq = Ui.button(this, "FAQ");
        faq.setOnClickListener(view -> startActivity(new Intent(this, AboutActivity.class)));
        page.addView(faq, Ui.matchWrap());
        Ui.addSpace(page, 8);
        Button close = Ui.button(this, "Close");
        close.setOnClickListener(view -> finish());
        page.addView(close, Ui.matchWrap());
        addBuildFooter(page);
        setContentView(scroll);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshBiometricState();
        refreshNotificationState();
    }

    private void refreshBiometricState() {
        if (biometricStatus == null || biometricButton == null) return;
        try {
            VaultState state = new VaultStore(this).load();
            boolean hasAnyWrap = state.bioVmkIv != null || state.bioVmkCiphertext != null;
            boolean hasCompleteWrap = state.bioVmkIv != null && state.bioVmkCiphertext != null;
            BiometricKeyManager.KeyInspection keyInspection =
                    new BiometricKeyManager.KeyInspection(
                            BiometricKeyManager.KeyStatus.MISSING,
                            BiometricKeyPolicy.PolicyReport.exact());
            byte[] iv = null;
            if (hasCompleteWrap) {
                try {
                    iv = CryptoEngine.fromBase64(state.bioVmkIv);
                    keyInspection = BiometricKeyManager.inspectDecryptionKey(iv);
                } catch (IllegalArgumentException exception) {
                    keyInspection = new BiometricKeyManager.KeyInspection(
                            BiometricKeyManager.KeyStatus.UNUSABLE,
                            BiometricKeyPolicy.PolicyReport.exact());
                } finally {
                    CryptoEngine.wipe(iv);
                }
            }

            if (!hasAnyWrap) {
                biometricUiState = BiometricUiState.DISABLED;
                biometricStatus.setText("Biometric unlock: Disabled");
                biometricStatus.setTextColor(Ui.MUTED);
                biometricButton.setText(BiometricEnrollmentUi.ADD_ACTION);
            } else if (hasCompleteWrap
                    && keyInspection.status == BiometricKeyManager.KeyStatus.USABLE) {
                boolean warning = keyInspection.policyReport.hasDeviations();
                boolean acknowledged = keyInspection.policyReport.isAcknowledgedBy(
                        state.bioPolicyAcknowledgements);
                if (warning && !acknowledged) {
                    biometricUiState = BiometricUiState.REVIEW_WARNING;
                    biometricStatus.setText(
                            "Biometric unlock: Enabled — protection review required");
                    biometricStatus.setTextColor(Ui.MUTED);
                    biometricButton.setText("Review biometric protection");
                } else if (warning) {
                    biometricUiState = BiometricUiState.ENABLED_WARNING;
                    biometricStatus.setText(
                            "Biometric unlock: Enabled — compatibility warning accepted");
                    biometricStatus.setTextColor(Ui.MUTED);
                    biometricButton.setText("Disable biometric unlock");
                } else {
                    biometricUiState = BiometricUiState.ENABLED;
                    biometricStatus.setText("Biometric unlock: Enabled");
                    biometricStatus.setTextColor(Ui.ACCENT);
                    biometricButton.setText("Disable biometric unlock");
                }
            } else if (keyInspection.status == BiometricKeyManager.KeyStatus.INVALIDATED) {
                biometricUiState = BiometricUiState.RESET_INVALIDATED;
                biometricStatus.setText("Biometric unlock: Reset required — enrolled biometrics changed");
                biometricStatus.setTextColor(Ui.DANGER);
                biometricButton.setText("Reset biometric unlock");
            } else {
                biometricUiState = BiometricUiState.RESET_UNAVAILABLE;
                biometricStatus.setText("Biometric unlock: Reset required — biometric key unavailable");
                biometricStatus.setTextColor(Ui.DANGER);
                biometricButton.setText("Reset biometric unlock");
            }
            biometricButton.setEnabled(!biometricOperation);
        } catch (VaultException exception) {
            biometricUiState = BiometricUiState.VAULT_UNAVAILABLE;
            biometricStatus.setText("Biometric unlock: Vault unavailable");
            biometricStatus.setTextColor(Ui.DANGER);
            biometricButton.setEnabled(false);
        }
    }

    private void refreshNotificationState() {
        if (notificationStatus == null || automationNotificationStatus == null
                || termuxPermissionStatus == null || notificationChannelButton == null
                || automationNotificationChannelButton == null) return;
        NotificationAccess.Status notificationState = NotificationAccess.status(
                this, VaultApplication.COMPLETION_CHANNEL);
        notificationStatus.setText("Completion notifications: " + notificationState.label);
        notificationStatus.setTextColor(notificationState.available ? Ui.ACCENT : Ui.DANGER);
        notificationChannelButton.setVisibility(
                NotificationAccess.shouldOfferChannelSettings(notificationState)
                        ? View.VISIBLE : View.GONE);

        NotificationAccess.Status automationState = NotificationAccess.status(
                this, VaultApplication.AUTOMATION_CHANNEL);
        automationNotificationStatus.setText(
                "Tasker authentication requests: " + automationState.label);
        automationNotificationStatus.setTextColor(
                automationState.available ? Ui.ACCENT : Ui.DANGER);
        automationNotificationChannelButton.setVisibility(
                NotificationAccess.shouldOfferChannelSettings(automationState)
                        ? View.VISIBLE : View.GONE);

        TermuxContract.Status termuxState = TermuxContract.status(this);
        termuxPermissionStatus.setText("Run commands in Termux: " + termuxState.label);
        termuxPermissionStatus.setTextColor(termuxState.available ? Ui.ACCENT : Ui.DANGER);
    }

    private void addSettingsHeading(LinearLayout page, String value) {
        TextView heading = Ui.heading(this, value, 18, Ui.TEXT);
        page.addView(heading, Ui.matchWrap());
        Ui.addSpace(page, 8);
    }

    private void addSubheading(LinearLayout page, String value) {
        TextView heading = Ui.heading(this, value, 16, Ui.TEXT);
        page.addView(heading, Ui.matchWrap());
        Ui.addSpace(page, 6);
    }

    private void addBuildFooter(LinearLayout page) {
        String versionName = "1.0.0";
        long versionCode = 1;
        try {
            PackageInfo info = getPackageManager().getPackageInfo(getPackageName(), 0);
            if (info.versionName != null && !info.versionName.trim().isEmpty()) {
                versionName = info.versionName;
            }
            versionCode = info.getLongVersionCode();
        } catch (PackageManager.NameNotFoundException ignored) {
            // The running package necessarily exists; fixed release values are a safe fallback.
        }

        String prefix = "Termux Vault " + versionName + " (" + versionCode + ")\n"
                + "Build date: " + getString(R.string.build_date) + "\n";
        SpannableString details = new SpannableString(prefix + PROJECT_URL);
        details.setSpan(new URLSpan(PROJECT_URL), prefix.length(), details.length(),
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        Ui.addSpace(page, 18);
        TextView footer = Ui.text(this, "", 12, Ui.MUTED);
        footer.setText(details);
        footer.setGravity(Gravity.CENTER_HORIZONTAL);
        enableReadOnlySelection(footer);
        footer.setMovementMethod(LinkMovementMethod.getInstance());
        footer.setHighlightColor(Ui.SURFACE);
        page.addView(footer, Ui.matchWrap());
    }

    private void beginAddBiometric() {
        BiometricAvailability.Status availability = BiometricAvailability.status(this);
        if (availability != BiometricAvailability.Status.STRONG_AVAILABLE) {
            BiometricAvailability.showUnavailable(this, availability,
                    biometricAvailabilityCallback());
            return;
        }
        beginBiometricEnrollment();
    }

    private void beginBiometricEnrollment() {
        biometricOperation = true;
        refreshBiometricState();
        UnlockCoordinator.unlock(this, AuthorizationReason.enableBiometric(),
                new UnlockCoordinator.Callback() {
            @Override
            public void onUnlocked(byte[] vmk, byte[] vaultFingerprint) {
                enrollBiometric(vmk, vaultFingerprint);
            }

            @Override
            public void onCancelled() {
                biometricOperation = false;
                refreshBiometricState();
            }
        });
    }

    private void enrollBiometric(byte[] vmk, byte[] vaultFingerprint) {
        BiometricEnrollment.enroll(this, vmk, vaultFingerprint,
                new BiometricEnrollment.Callback() {
            @Override
            public void onEnabled() {
                biometricOperation = false;
                refreshBiometricState();
                boolean warningAccepted = biometricUiState == BiometricUiState.ENABLED_WARNING;
                Ui.showSecure(new AlertDialog.Builder(SettingsActivity.this)
                        .setTitle("Biometric unlock enabled")
                        .setMessage(warningAccepted
                                ? "A Class 3 biometric can now unlock protected commands with the "
                                        + "device-specific protection findings you reviewed."
                                : "A Class 3 biometric can now unlock protected commands.")
                        .setPositiveButton("OK", null));
            }

            @Override
            public void onCancelled() {
                biometricOperation = false;
                refreshBiometricState();
            }

            @Override
            public void onUnavailable(BiometricEnrollment.Failure failure) {
                biometricOperation = false;
                refreshBiometricState();
                showBiometricUnavailable(failure);
            }
        });
    }

    private void showBiometricUnavailable(BiometricEnrollment.Failure failure) {
        if (BiometricEnrollmentUi.showAvailabilityFailure(this, failure,
                biometricAvailabilityCallback())) return;
        BiometricEnrollmentUi.showFailure(this, failure,
                "The vault is unchanged and remains available with its vault passphrase.",
                () -> {});
    }

    private BiometricAvailability.Callback biometricAvailabilityCallback() {
        return new BiometricAvailability.Callback() {
            @Override
            public void onContinueWithPassphrase() {
                // Settings remains on the Disabled state.
            }

            @Override
            public void onOpenBiometricSettings() {
                if (!BiometricAvailability.openSettings(SettingsActivity.this)) {
                    Ui.showError(SettingsActivity.this,
                            "Android biometric settings could not be opened. The vault remains "
                                    + "available with its passphrase.");
                }
            }
        };
    }

    private void showBiometricPolicyReview() {
        try {
            VaultState state = new VaultStore(this).load();
            if (state.bioVmkIv == null || state.bioVmkCiphertext == null) {
                refreshBiometricState();
                return;
            }
            byte[] iv = null;
            BiometricKeyManager.KeyInspection inspection;
            try {
                iv = CryptoEngine.fromBase64(state.bioVmkIv);
                inspection = BiometricKeyManager.inspectDecryptionKey(iv);
            } finally {
                CryptoEngine.wipe(iv);
            }
            if (inspection.status != BiometricKeyManager.KeyStatus.USABLE) {
                refreshBiometricState();
                return;
            }
            if (!inspection.policyReport.hasDeviations()
                    || inspection.policyReport.isAcknowledgedBy(
                            state.bioPolicyAcknowledgements)) {
                refreshBiometricState();
                return;
            }

            AlertDialog dialog = BiometricPolicyWarningDialog.create(this,
                    inspection.policyReport, "Review biometric protection for this vault",
                    "Your vault passphrase is required before Termux Vault records this choice.",
                    "Review with passphrase", "Keep passphrase only",
                    new BiometricPolicyWarningDialog.Callback() {
                        @Override
                        public void onContinue() {
                            beginBiometricPolicyAuthorization(
                                    inspection.policyReport.acceptanceTokens());
                        }

                        @Override
                        public void onDecline() {
                            beginRemoveBiometric();
                        }

                        @Override
                        public void onCancel() {
                            // Leave the review pending; protected actions will use the passphrase.
                        }
                    });
            dialog.show();
        } catch (VaultException | IllegalArgumentException exception) {
            refreshBiometricState();
            Ui.showError(this, "Biometric protection details could not be reviewed. The vault "
                    + "remains available with its passphrase.");
        }
    }

    private void beginBiometricPolicyAuthorization(
            java.util.List<String> displayedPolicyTokens) {
        biometricOperation = true;
        refreshBiometricState();
        UnlockCoordinator.unlockWithPassphraseOnly(this,
                "Accept the displayed biometric protection findings for this vault",
                new UnlockCoordinator.Callback() {
                    @Override
                    public void onUnlocked(byte[] vmk, byte[] vaultFingerprint) {
                        CryptoEngine.wipe(vmk);
                        persistBiometricPolicyReview(
                                vaultFingerprint, displayedPolicyTokens);
                    }

                    @Override
                    public void onCancelled() {
                        biometricOperation = false;
                        refreshBiometricState();
                    }
                });
    }

    /** Takes ownership of and wipes {@code vaultFingerprint}. */
    private void persistBiometricPolicyReview(byte[] vaultFingerprint,
                                              java.util.List<String> displayedPolicyTokens) {
        new Thread(() -> {
            VaultException failure = null;
            try {
                if (!isSecureSessionActive()) throw new VaultException("Cancelled");
                VaultStore store = new VaultStore(this);
                PolicyReviewState reviewState = store.readIfUnchanged(
                        vaultFingerprint, state -> {
                            if (state.bioVmkIv == null || state.bioVmkCiphertext == null) {
                                throw new VaultException("Biometric wrapper is unavailable");
                            }
                            return new PolicyReviewState(
                                    state.bioVmkIv, state.bioVmkCiphertext);
                        });
                byte[] iv = null;
                BiometricKeyManager.KeyInspection inspection;
                try {
                    iv = CryptoEngine.fromBase64(reviewState.iv);
                    inspection = BiometricKeyManager.inspectDecryptionKey(iv);
                } catch (IllegalArgumentException exception) {
                    throw new VaultException("Biometric wrapper is invalid", exception);
                } finally {
                    CryptoEngine.wipe(iv);
                }
                if (inspection.status != BiometricKeyManager.KeyStatus.USABLE) {
                    throw new VaultException("Biometric key is unavailable");
                }
                if (!inspection.policyReport.acceptanceTokens().equals(displayedPolicyTokens)) {
                    throw new VaultException("Biometric protection findings changed");
                }
                if (inspection.policyReport.hasDeviations()) {
                    store.mutateIfUnchanged(vaultFingerprint, state -> {
                        if (!isSecureSessionActive()
                                || !reviewState.iv.equals(state.bioVmkIv)
                                || !reviewState.ciphertext.equals(state.bioVmkCiphertext)) {
                            throw new VaultException("Biometric review expired");
                        }
                        inspection.policyReport.mergeAcknowledgementsInto(
                                state.bioPolicyAcknowledgements,
                                VaultStore.MAX_BIOMETRIC_POLICY_ACKNOWLEDGEMENTS);
                    });
                }
            } catch (VaultException exception) {
                failure = exception;
            } finally {
                CryptoEngine.wipe(vaultFingerprint);
            }
            VaultException finalFailure = failure;
            runOnUiThread(() -> {
                biometricOperation = false;
                if (!isSecureSessionActive()) return;
                refreshBiometricState();
                if (finalFailure != null) {
                    if ("Biometric protection findings changed"
                            .equals(finalFailure.getMessage())) {
                        Ui.showError(this, "Biometric protection findings changed after the "
                                + "warning was displayed. Open Review biometric protection "
                                + "again to see the current findings.");
                        return;
                    }
                    Ui.showError(this, finalFailure.isStateChanged()
                            ? "The vault changed during biometric review. Review the current "
                                    + "state and try again."
                            : "The biometric protection choice could not be saved. The vault is "
                                    + "unchanged and remains available with its passphrase.");
                    return;
                }
                Ui.showSecure(new AlertDialog.Builder(this)
                        .setTitle("Biometric protection reviewed")
                        .setMessage("Biometric unlock remains enabled with the exact "
                                + "device-specific findings you reviewed.")
                        .setPositiveButton("OK", null));
            });
        }, "vault-biometric-policy-review").start();
    }

    private void showBiometricReset() {
        String explanation = biometricUiState == BiometricUiState.RESET_INVALIDATED
                ? "Android invalidated biometric unlock because enrolled biometrics changed. "
                : "The biometric key is no longer usable. ";
        explanation += "Enter the vault passphrase to remove the unusable biometric material. "
                + "Biometric unlock will return to its initial Disabled state.";

        showBiometricRemovalDialog(true, explanation);
    }

    private void beginRemoveBiometric() {
        showBiometricRemovalDialog(false,
                "Enter the vault passphrase. After biometric unlock is disabled, protected "
                        + "commands require the vault passphrase.");
    }

    private void showBiometricRemovalDialog(boolean reset, String explanation) {

        LinearLayout body = dialogBody();
        body.addView(Ui.text(this, explanation, 14, Ui.MUTED), Ui.matchWrap());
        Ui.addSpace(body, 8);
        PasswordInput passphraseInput = passphraseField("Vault passphrase");
        EditText passphrase = passphraseInput.editText();
        body.addView(passphraseInput, Ui.matchWrap());
        TextView error = Ui.text(this, "", 13, Ui.DANGER);
        body.addView(error, Ui.matchWrap());

        AlertDialog dialog = Ui.createSecure(new AlertDialog.Builder(this)
                .setTitle(reset ? "Reset biometric unlock" : "Disable biometric unlock")
                .setView(body)
                .setPositiveButton(reset ? "Reset" : "Disable", null)
                .setNegativeButton("Cancel", null)
        );
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE)
                .setOnClickListener(view -> {
                    char[] entered = Ui.readChars(passphrase);
                    Ui.clear(passphrase);
                    if (entered.length == 0) {
                        CryptoEngine.wipe(entered);
                        error.setText("Vault passphrase is incorrect.");
                        return;
                    }
                    biometricOperation = true;
                    setDialogBusy(dialog, error, reset ? "Resetting…" : "Disabling…");
                    new Thread(() -> removeBiometricWithPassphrase(
                            entered, dialog, error, reset),
                            reset ? "vault-biometric-reset" : "vault-biometric-remove").start();
                }));
        dialog.setOnDismissListener(ignored -> Ui.clear(passphrase));
        dialog.show();
    }

    private void removeBiometricWithPassphrase(char[] passphrase, AlertDialog dialog,
                                               TextView error, boolean reset) {
        VaultException failure = null;
        boolean keystoreRemoved = true;
        try {
            new VaultStore(this).mutate(state -> {
                byte[] vmk = VaultService.unlockWithPassphrase(state, passphrase);
                try {
                    state.bioVmkIv = null;
                    state.bioVmkCiphertext = null;
                    state.bioPolicyAcknowledgements.clear();
                } finally {
                    CryptoEngine.wipe(vmk);
                }
            });
            try {
                BiometricKeyManager.deleteKey();
            } catch (GeneralSecurityException | RuntimeException exception) {
                keystoreRemoved = false;
            }
        } catch (VaultException exception) {
            failure = exception;
        } finally {
            CryptoEngine.wipe(passphrase);
        }

        VaultException finalFailure = failure;
        boolean finalKeystoreRemoved = keystoreRemoved;
        runOnUiThread(() -> {
            biometricOperation = false;
            if (isFinishing() || isDestroyed()) return;
            refreshBiometricState();
            if (finalFailure != null) {
                String message = finalFailure.isAuthenticationFailure()
                        ? "Vault passphrase is incorrect."
                        : (reset ? "Biometric unlock could not be reset."
                                : "Biometric unlock could not be disabled.");
                setDialogReady(dialog, error, message);
                return;
            }
            dialog.dismiss();
            Ui.showSecure(new AlertDialog.Builder(this)
                    .setTitle(reset ? "Biometric unlock reset" : "Biometric unlock disabled")
                    .setMessage((reset
                            ? "Biometric unlock returned to its initial Disabled state."
                            : "Biometric unlock is disabled. Protected commands now require the "
                                    + "vault passphrase.")
                            + (finalKeystoreRemoved ? ""
                            : " The unusable vault wrapper was removed, but deletion of the obsolete "
                            + "Android Keystore key could not be confirmed; without the wrapper it cannot "
                            + "unlock the vault."))
                    .setPositiveButton("OK", null));
        });
    }

    private void showPassphraseChange() {
        LinearLayout body = dialogBody();
        body.addView(Ui.text(this,
                "Your new vault passphrase will protect a new encryption key for every command. "
                        + "A copy of the vault that was encrypted with the previous passphrase cannot "
                        + "decrypt commands after this change. Biometric unlock, if enabled, is "
                        + "disabled because it wrapped the previous key; you can enable it again "
                        + "afterward.\n\n"
                        + PassphraseWarning.guidance(),
                14, Ui.MUTED), Ui.matchWrap());
        Ui.addSpace(body, 8);
        PasswordInput currentInput = passphraseField("Current vault passphrase");
        PasswordInput firstInput = passphraseField("New vault passphrase");
        PasswordInput secondInput = passphraseField("Confirm new vault passphrase");
        EditText current = currentInput.editText();
        EditText first = firstInput.editText();
        EditText second = secondInput.editText();
        body.addView(currentInput, Ui.matchWrap());
        body.addView(firstInput, Ui.matchWrap());
        body.addView(secondInput, Ui.matchWrap());
        TextView error = Ui.text(this, "", 13, Ui.DANGER);
        body.addView(error, Ui.matchWrap());

        AlertDialog dialog = Ui.createSecure(new AlertDialog.Builder(this)
                .setTitle("Change vault passphrase")
                .setView(body)
                .setPositiveButton("Change", null)
                .setNegativeButton("Cancel", null)
        );
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE)
                .setOnClickListener(view -> {
                    char[] oldPassphrase = Ui.readChars(current);
                    char[] newPassphrase = Ui.readChars(first);
                    char[] confirmation = Ui.readChars(second);
                    Ui.clear(current);
                    Ui.clear(first);
                    Ui.clear(second);
                    if (oldPassphrase.length == 0) {
                        wipeAll(oldPassphrase, newPassphrase, confirmation);
                        error.setText("Vault passphrase is incorrect.");
                        return;
                    }
                    if (newPassphrase.length == 0 || !Arrays.equals(newPassphrase, confirmation)) {
                        wipeAll(oldPassphrase, newPassphrase, confirmation);
                        error.setText("Use matching, non-empty vault passphrases.");
                        return;
                    }
                    CryptoEngine.wipe(confirmation);
                    if (PassphraseWarning.isTooWeak(newPassphrase)) {
                        PassphraseWarning.show(this, PassphraseWarning.Purpose.VAULT,
                                useAnyway -> {
                                    if (!useAnyway) {
                                        wipeAll(oldPassphrase, newPassphrase);
                                        if (isSecureSessionActive()) {
                                            error.setText("Choose a stronger vault passphrase.");
                                            first.post(() -> {
                                                if (!isSecureSessionActive()
                                                        || !dialog.isShowing()
                                                        || !first.isShown()) return;
                                                first.requestFocus();
                                                first.setSelection(0);
                                            });
                                        }
                                        return;
                                    }
                                    startPassphraseChange(oldPassphrase, newPassphrase,
                                            dialog, error);
                                });
                        return;
                    }
                    startPassphraseChange(oldPassphrase, newPassphrase, dialog, error);
                }));
        dialog.setOnDismissListener(ignored -> {
            Ui.clear(current);
            Ui.clear(first);
            Ui.clear(second);
        });
        dialog.show();
    }

    private void startPassphraseChange(char[] oldPassphrase, char[] newPassphrase,
                                       AlertDialog dialog, TextView error) {
        if (isFinishing() || isDestroyed()) {
            wipeAll(oldPassphrase, newPassphrase);
            return;
        }
        setDialogBusy(dialog, error, "Changing…");
        new Thread(() -> changePassphrase(oldPassphrase, newPassphrase, dialog, error),
                "vault-change-kdf").start();
    }

    private void changePassphrase(char[] oldPassphrase, char[] newPassphrase,
                                  AlertDialog dialog, TextView error) {
        VaultException failure = null;
        boolean biometricCleared = false;
        boolean keystoreRemoved = true;
        try {
            boolean[] cleared = {false};
            new VaultStore(this).mutate(state -> {
                byte[] vmk = VaultService.unlockWithPassphrase(state, oldPassphrase);
                try {
                    cleared[0] = VaultService.rotateMasterKey(state, vmk, newPassphrase);
                } finally {
                    CryptoEngine.wipe(vmk);
                }
            });
            biometricCleared = cleared[0];
            if (biometricCleared) {
                try {
                    BiometricKeyManager.deleteKey();
                } catch (GeneralSecurityException | RuntimeException exception) {
                    keystoreRemoved = false;
                }
            }
        } catch (VaultException exception) {
            failure = exception;
        } finally {
            CryptoEngine.wipe(oldPassphrase);
            CryptoEngine.wipe(newPassphrase);
        }
        VaultException finalFailure = failure;
        boolean finalBiometricCleared = biometricCleared;
        boolean finalKeystoreRemoved = keystoreRemoved;
        runOnUiThread(() -> {
            if (isFinishing() || isDestroyed()) return;
            if (finalFailure != null) {
                setDialogReady(dialog, error, finalFailure.isAuthenticationFailure()
                        ? "Vault passphrase is incorrect."
                        : "The vault passphrase could not be changed.");
                return;
            }
            refreshBiometricState();
            dialog.dismiss();
            String message = "Commands are now protected by a new vault key. The previous "
                    + "passphrase cannot decrypt this vault.";
            if (finalBiometricCleared) {
                message += " Biometric unlock was disabled because it wrapped the previous key. "
                        + "You can enable it again from Settings.";
                if (!finalKeystoreRemoved) {
                    message += " The Android Keystore key could not be confirmed deleted; without "
                            + "the wrapper it cannot unlock the vault.";
                }
            }
            Ui.showSecure(new AlertDialog.Builder(this)
                    .setTitle("Vault passphrase changed")
                    .setMessage(message)
                    .setPositiveButton("OK", null));
        });
    }

    private void showDestructiveDialog(boolean resetVault) {
        String confirmationText = resetVault ? "RESET VAULT" : "DELETE ALL";
        LinearLayout body = dialogBody();
        TextView warning = Ui.text(this, resetVault
                        ? "This permanently removes the vault, every entry, Termux trust, and "
                                + "biometric unlock configuration. Android permissions remain. "
                                + "Flash storage cannot guarantee forensic erasure."
                        : "This permanently removes every command entry. The vault passphrase, "
                                + "biometric unlock, and Termux trust remain configured. Flash "
                                + "storage cannot guarantee forensic erasure.",
                14, Ui.DANGER);
        warning.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        body.addView(warning, Ui.matchWrap());
        Ui.addSpace(body, 10);
        PasswordInput passphraseInput = passphraseField("Vault passphrase");
        EditText passphrase = passphraseInput.editText();
        body.addView(passphraseInput, Ui.matchWrap());
        EditText confirmation = Ui.textField(this, "Type " + confirmationText, false);
        confirmation.setImeOptions(EditorInfo.IME_ACTION_DONE
                | EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                | EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        body.addView(confirmation, Ui.matchWrap());
        TextView status = Ui.text(this, "", 13, Ui.DANGER);
        body.addView(status, Ui.matchWrap());

        AlertDialog dialog = Ui.createSecure(new AlertDialog.Builder(this)
                .setTitle(resetVault ? "Reset vault completely?" : "Delete all entries?")
                .setView(body)
                .setPositiveButton(resetVault ? "Reset vault" : "Delete all", null)
                .setNegativeButton("Cancel", null)
        );
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE)
                .setOnClickListener(view -> {
                    char[] entered = Ui.readChars(passphrase);
                    char[] typed = Ui.readChars(confirmation);
                    Ui.clear(passphrase);
                    Ui.clear(confirmation);
                    boolean confirmationMatches = Arrays.equals(
                            typed, confirmationText.toCharArray());
                    CryptoEngine.wipe(typed);
                    if (entered.length == 0) {
                        CryptoEngine.wipe(entered);
                        status.setText("Vault passphrase is incorrect.");
                        return;
                    }
                    if (!confirmationMatches) {
                        CryptoEngine.wipe(entered);
                        status.setText("Type " + confirmationText + " exactly to continue.");
                        return;
                    }
                    setDialogBusy(dialog, status,
                            resetVault ? "Resetting vault…" : "Deleting entries…");
                    new Thread(() -> performDestructiveAction(
                            resetVault, entered, dialog, status),
                            resetVault ? "vault-reset" : "vault-delete-entries").start();
                }));
        dialog.setOnDismissListener(ignored -> {
            Ui.clear(passphrase);
            Ui.clear(confirmation);
        });
        dialog.show();
    }

    private void performDestructiveAction(boolean resetVault, char[] passphrase,
                                          AlertDialog dialog, TextView status) {
        VaultException failure = null;
        int removed = 0;
        boolean committed = false;
        boolean cleanupComplete = true;
        try {
            VaultStore store = new VaultStore(this);
            if (resetVault) {
                store.deleteAuthenticated(passphrase);
            } else {
                removed = store.clearEntriesAuthenticated(passphrase);
            }
            committed = true;
        } catch (VaultException exception) {
            failure = exception;
        } finally {
            CryptoEngine.wipe(passphrase);
        }

        if (committed) {
            cleanupComplete &= runCleanup(() -> CompletionStore.clearAll(this));
            try {
                getSystemService(NotificationManager.class).cancelAll();
            } catch (RuntimeException exception) {
                cleanupComplete = false;
            }
            cleanupComplete &= runCleanup(() -> CommandWidgetProvider.resetAllToChoose(this));
            if (resetVault) {
                cleanupComplete &= runCleanup(() -> TermuxContract.clearRequestHistory(this));
                cleanupComplete &= runCleanup(() -> AutomationReceiver.clearThrottle(this));
                try {
                    BiometricKeyManager.deleteKey();
                } catch (GeneralSecurityException | RuntimeException exception) {
                    cleanupComplete = false;
                }
            }
        }

        VaultException finalFailure = failure;
        int finalRemoved = removed;
        boolean finalCommitted = committed;
        boolean finalCleanupComplete = cleanupComplete;
        runOnUiThread(() -> {
            if (isFinishing() || isDestroyed()) return;
            if (!finalCommitted) {
                String message = finalFailure != null
                        && finalFailure.isAuthenticationFailure()
                        ? "Vault passphrase is incorrect."
                        : (resetVault ? "The vault could not be reset."
                                : "The entries could not be deleted.");
                setDialogReady(dialog, status, message);
                return;
            }
            dialog.dismiss();
            if (resetVault) {
                if (!finalCleanupComplete) {
                    Ui.showSecure(new AlertDialog.Builder(this)
                            .setTitle("Vault reset with a warning")
                            .setMessage("The vault and protected entries were deleted, but some "
                                    + "Android housekeeping could not be confirmed. Old widgets "
                                    + "or notifications may need to be removed manually.")
                            .setCancelable(false)
                            .setPositiveButton("Continue to setup",
                                    (warning, which) -> openSetupAfterReset()));
                } else {
                    openSetupAfterReset();
                }
                return;
            }
            String message = finalRemoved + (finalRemoved == 1
                    ? " entry was permanently removed."
                    : " entries were permanently removed.");
            if (!finalCleanupComplete) {
                message += " Some Android housekeeping could not be confirmed; the entries are "
                        + "still deleted.";
            }
            Ui.showSecure(new AlertDialog.Builder(this)
                    .setTitle("All entries deleted")
                    .setMessage(message)
                    .setPositiveButton("OK", null));
        });
    }

    private void openSetupAfterReset() {
        Intent setup = new Intent(this, SetupActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(setup);
        finish();
    }

    private static boolean runCleanup(Cleanup cleanup) {
        try {
            cleanup.run();
            return true;
        } catch (VaultException | RuntimeException exception) {
            return false;
        }
    }

    private interface Cleanup {
        void run() throws VaultException;
    }

    private LinearLayout dialogBody() {
        LinearLayout body = Ui.page(this);
        body.setPadding(Ui.dp(this, 20), Ui.dp(this, 4), Ui.dp(this, 20), 0);
        return body;
    }

    private PasswordInput passphraseField(String hint) {
        PasswordInput input = new PasswordInput(this, hint);
        input.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                | EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        return input;
    }

    private static void setDialogBusy(AlertDialog dialog, TextView status, String message) {
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);
        dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setEnabled(false);
        dialog.setCancelable(false);
        dialog.setCanceledOnTouchOutside(false);
        status.setText(message);
    }

    private static void setDialogReady(AlertDialog dialog, TextView status, String message) {
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(true);
        dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setEnabled(true);
        dialog.setCancelable(true);
        dialog.setCanceledOnTouchOutside(true);
        status.setText(message);
    }

    private static void wipeAll(char[]... values) {
        for (char[] value : values) CryptoEngine.wipe(value);
    }

    @Override
    protected void onSecureForegroundLost() {
        // Sensitive dialog fields are cleared by SecureActivity before this hook. Any already
        // running atomic vault write may finish, but all late UI callbacks are rejected.
        finish();
    }
}
