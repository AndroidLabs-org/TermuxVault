package app.termuxvault.secure;

import android.annotation.SuppressLint;

import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

@SuppressLint("SetTextI18n")
public final class SetupActivity extends SecureActivity {
    private EditText passphrase;
    private EditText confirmation;
    private Button createButton;
    private TextView status;
    private VaultService.Creation pendingCreation;
    private byte[] pendingFingerprint;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        VaultStore store = new VaultStore(this);
        if (store.exists()) {
            openMain();
            return;
        }

        ScrollView scroll = new ScrollView(this);
        LinearLayout page = Ui.page(this);
        scroll.addView(page);
        page.addView(Ui.title(this, "Create your vault"), Ui.matchWrap());
        page.addView(Ui.text(this,
                "Your vault passphrase cryptographically protects the key that encrypts every "
                        + "command. It is not just an app lock. There is no recovery if you "
                        + "forget it.",
                15, Ui.MUTED), Ui.matchWrap());
        Ui.addSpace(page, 8);
        page.addView(Ui.text(this,
                "Optional biometric unlock protects another encrypted copy of the vault key with "
                        + "an Android Keystore key. Termux Vault requests and checks Class 3, "
                        + "hardware-backed protection before enabling it, and explains any protection "
                        + "it cannot confirm. The decrypted key is held only briefly in memory after "
                        + "successful biometric authentication. Android device credentials and Class 2 "
                        + "biometrics are never accepted for this key.",
                14, Ui.MUTED), Ui.matchWrap());
        Ui.addSpace(page, 18);

        PasswordInput passphraseInput = new PasswordInput(this, "Vault passphrase");
        PasswordInput confirmationInput = new PasswordInput(this, "Confirm vault passphrase");
        passphrase = passphraseInput.editText();
        confirmation = confirmationInput.editText();
        page.addView(passphraseInput, Ui.matchWrap());
        page.addView(confirmationInput, Ui.matchWrap());
        Ui.addSpace(page, 8);
        page.addView(Ui.text(this,
                PassphraseWarning.guidance(),
                13, Ui.MUTED), Ui.matchWrap());
        Ui.addSpace(page, 16);
        createButton = Ui.button(this, "Create vault");
        page.addView(createButton, Ui.matchWrap());
        status = Ui.text(this, "", 13, Ui.DANGER);
        page.addView(status, Ui.matchWrap());
        createButton.setOnClickListener(view -> beginSetup());
        setContentView(scroll);
    }

    private void beginSetup() {
        char[] first = Ui.readChars(passphrase);
        char[] second = Ui.readChars(confirmation);
        Ui.clear(passphrase);
        Ui.clear(confirmation);
        if (first.length == 0 || !Arrays.equals(first, second)) {
            CryptoEngine.wipe(first);
            CryptoEngine.wipe(second);
            status.setTextColor(Ui.DANGER);
            status.setText("Use matching, non-empty passphrases.");
            return;
        }
        CryptoEngine.wipe(second);
        if (PassphraseWarning.isTooWeak(first)) {
            PassphraseWarning.show(this, PassphraseWarning.Purpose.VAULT, useAnyway -> {
                if (!useAnyway) {
                    CryptoEngine.wipe(first);
                    if (isSecureSessionActive()) {
                        status.setTextColor(Ui.MUTED);
                        status.setText("Choose a stronger vault passphrase.");
                        passphrase.post(() -> {
                            if (!isSecureSessionActive() || !passphrase.isShown()) return;
                            passphrase.requestFocus();
                            passphrase.setSelection(0);
                        });
                    }
                    return;
                }
                startVaultCreation(first);
            });
            return;
        }
        startVaultCreation(first);
    }

    private void startVaultCreation(char[] first) {
        if (isFinishing() || isDestroyed()) {
            CryptoEngine.wipe(first);
            return;
        }
        createButton.setEnabled(false);
        status.setTextColor(Ui.MUTED);
        status.setText("Hardening the vault…");
        new Thread(() -> createPasswordVault(first), "vault-setup-kdf").start();
    }

    private void createPasswordVault(char[] first) {
        VaultService.Creation creation = null;
        byte[] fingerprint = null;
        VaultException failure = null;
        char[] sampleCommand = SampleCommand.COMMAND.toCharArray();
        try {
            creation = VaultService.create(first);
            creation.state.entries.add(VaultService.encryptNewEntry(creation.vmk,
                    SampleCommand.TITLE, EntryIcons.DEFAULT, sampleCommand,
                    SampleCommand.PAUSE_AFTER_SUCCESS, SampleCommand.NOTIFY_WHEN_FINISHED,
                    SampleCommand.HIDE_TERMINAL_OUTPUT));
            if (!TermuxSetupOnboarding.markPending(this)) {
                throw new VaultException("Vault onboarding state could not be saved");
            }
            fingerprint = new VaultStore(this).saveInitialAndFingerprint(creation.state);
            try {
                BiometricKeyManager.deleteKey();
            } catch (GeneralSecurityException ignored) {
                // A leftover key has no usable wrapper and cannot unlock this vault.
            }
        } catch (VaultException exception) {
            failure = exception;
        } finally {
            CryptoEngine.wipe(sampleCommand);
            CryptoEngine.wipe(first);
        }
        VaultService.Creation result = creation;
        byte[] resultFingerprint = fingerprint;
        VaultException finalFailure = failure;
        runOnUiThread(() -> {
            if (isFinishing() || isDestroyed()) {
                if (result != null) result.wipe();
                CryptoEngine.wipe(resultFingerprint);
                return;
            }
            if (finalFailure != null) {
                if (result != null) result.wipe();
                CryptoEngine.wipe(resultFingerprint);
                status.setTextColor(Ui.DANGER);
                status.setText("Vault creation failed. No vault was activated.");
                createButton.setEnabled(true);
                return;
            }
            pendingCreation = result;
            pendingFingerprint = resultFingerprint;
            status.setTextColor(Ui.ACCENT);
            status.setText("Vault created.");
            offerBiometric();
        });
    }

    private void offerBiometric() {
        AtomicBoolean answered = new AtomicBoolean(false);
        AlertDialog dialog = Ui.createSecure(new AlertDialog.Builder(this)
                .setTitle("Vault created")
                .setMessage(BiometricEnrollmentUi.OFFER)
                .setPositiveButton(BiometricEnrollmentUi.ADD_ACTION, (ignored, which) -> {
                    if (answered.compareAndSet(false, true)) beginBiometricEnrollment();
                })
                .setNegativeButton("Not now", (ignored, which) -> {
                    if (answered.compareAndSet(false, true)) finishPasswordOnly();
                })
                .setOnCancelListener(ignored -> {
                    if (answered.compareAndSet(false, true)) finishPasswordOnly();
                })
        );
        dialog.show();
    }

    private void beginBiometricEnrollment() {
        BiometricAvailability.Status availability = BiometricAvailability.status(this);
        if (availability != BiometricAvailability.Status.STRONG_AVAILABLE) {
            showBiometricAvailabilityThenContinue(availability, true);
            return;
        }
        VaultService.Creation creation = pendingCreation;
        byte[] fingerprint = pendingFingerprint;
        pendingCreation = null;
        pendingFingerprint = null;
        if (creation == null || fingerprint == null) {
            if (creation != null) creation.wipe();
            CryptoEngine.wipe(fingerprint);
            openMain();
            return;
        }
        BiometricEnrollment.enroll(this, creation.vmk, fingerprint,
                new BiometricEnrollment.Callback() {
            @Override
            public void onEnabled() {
                openMain();
            }

            @Override
            public void onCancelled() {
                openMain();
            }

            @Override
            public void onUnavailable(BiometricEnrollment.Failure failure) {
                showBiometricUnavailableThenOpen(failure);
            }
        });
    }

    private void finishPasswordOnly() {
        finishPasswordOnly(false);
    }

    private void finishPasswordOnly(boolean openBiometricSettings) {
        if (pendingCreation != null) {
            pendingCreation.wipe();
            pendingCreation = null;
        }
        CryptoEngine.wipe(pendingFingerprint);
        pendingFingerprint = null;
        openMain(openBiometricSettings);
    }

    private void showBiometricUnavailableThenOpen(BiometricEnrollment.Failure failure) {
        if (isFinishing() || isDestroyed()) return;
        if (BiometricEnrollmentUi.showAvailabilityFailure(this, failure,
                biometricAvailabilityThenContinue(false))) return;
        BiometricEnrollmentUi.showFailure(this, failure,
                "The vault is ready with its passphrase, and biometrics can be added later in "
                        + "Settings.",
                this::openMain);
    }

    private void showBiometricAvailabilityThenContinue(BiometricAvailability.Status status,
                                                        boolean ownsPendingCreation) {
        BiometricAvailability.showUnavailable(this, status,
                biometricAvailabilityThenContinue(ownsPendingCreation));
    }

    private BiometricAvailability.Callback biometricAvailabilityThenContinue(
            boolean ownsPendingCreation) {
        return new BiometricAvailability.Callback() {
            @Override
            public void onContinueWithPassphrase() {
                if (ownsPendingCreation) finishPasswordOnly();
                else openMain();
            }

            @Override
            public void onOpenBiometricSettings() {
                if (ownsPendingCreation) finishPasswordOnly(true);
                else openMain(true);
            }
        };
    }

    private void openMain() {
        openMain(false);
    }

    private void openMain(boolean openBiometricSettings) {
        if (!isSecureSessionActive()) return;
        Intent main = openBiometricSettings
                ? MainActivity.afterSetupBiometricSettingsIntent(this)
                : new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        startActivity(main);
        finish();
    }

    @Override
    protected void onSecureForegroundLost() {
        // The KDF, if already running, owns and wipes its local arrays. Marking this Activity as
        // finishing makes its late callback wipe the produced key instead of showing another UI.
        finish();
        if (pendingCreation != null) {
            pendingCreation.wipe();
            pendingCreation = null;
        }
        CryptoEngine.wipe(pendingFingerprint);
        pendingFingerprint = null;
    }

    @Override
    protected void onDestroy() {
        if (pendingCreation != null) {
            pendingCreation.wipe();
            pendingCreation = null;
        }
        CryptoEngine.wipe(pendingFingerprint);
        pendingFingerprint = null;
        if (passphrase != null) Ui.clear(passphrase);
        if (confirmation != null) Ui.clear(confirmation);
        super.onDestroy();
    }
}
