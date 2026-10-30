package app.termuxvault.secure;

import android.annotation.SuppressLint;

import android.app.AlertDialog;
import android.graphics.Typeface;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.CancellationSignal;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.security.GeneralSecurityException;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Cipher;

@SuppressLint("SetTextI18n")
final class UnlockCoordinator {
    interface ReasonResolver {
        String resolve(VaultState state) throws VaultException;
    }

    enum EntryAction {
        EDIT,
        RUN,
        TRUST_AND_RUN,
        DELETE
    }

    interface Callback {
        /** Both arrays are owned by the callback and must be wiped after the protected action. */
        void onUnlocked(byte[] vmk, byte[] vaultFingerprint);

        void onCancelled();
    }

    private static final class UnlockedVault {
        byte[] vmk;
        byte[] fingerprint;

        UnlockedVault(byte[] vmk, byte[] fingerprint) {
            this.vmk = vmk;
            this.fingerprint = fingerprint;
        }

        void wipe() {
            CryptoEngine.wipe(vmk);
            CryptoEngine.wipe(fingerprint);
            vmk = null;
            fingerprint = null;
        }
    }

    private static final class AuthenticatedSnapshot {
        final VaultState state;
        final String reason;
        byte[] fingerprint;

        AuthenticatedSnapshot(VaultState state, byte[] fingerprint, String reason) {
            this.state = state;
            this.fingerprint = fingerprint;
            this.reason = reason;
        }
    }

    private static final class SnapshotVerificationException extends Exception {
        SnapshotVerificationException(VaultException cause) {
            super(cause);
        }
    }

    /** Owns one authorization request across biometric and passphrase fallback routes. */
    private static final class UnlockSession {
        private final SecureActivity activity;
        private final Callback callback;
        private final AtomicBoolean terminal = new AtomicBoolean(false);
        private final Runnable foregroundObserver = this::cancel;
        private CancellationSignal cancellation;
        private AlertDialog dialog;
        private Runnable phaseCleanup;

        UnlockSession(SecureActivity activity, Callback callback) {
            this.activity = activity;
            this.callback = callback;
        }

        boolean begin() {
            if (activity.addForegroundLossObserver(foregroundObserver)) return true;
            terminal.set(true);
            callback.onCancelled();
            return false;
        }

        boolean isActive() {
            return !terminal.get() && activity.isSecureSessionActive();
        }

        void setPhase(CancellationSignal nextCancellation, AlertDialog nextDialog,
                      Runnable nextCleanup) {
            cancellation = nextCancellation;
            dialog = nextDialog;
            phaseCleanup = nextCleanup;
            if (!isActive()) cancel();
        }

        void clearPhase() {
            cancellation = null;
            dialog = null;
            phaseCleanup = null;
        }

        void cancel() {
            if (!terminal.compareAndSet(false, true)) return;
            activity.removeForegroundLossObserver(foregroundObserver);
            CancellationSignal signal = cancellation;
            AlertDialog activeDialog = dialog;
            Runnable cleanup = phaseCleanup;
            clearPhase();
            if (signal != null && !signal.isCanceled()) signal.cancel();
            if (cleanup != null) cleanup.run();
            if (activeDialog != null && activeDialog.isShowing()) activeDialog.dismiss();
            callback.onCancelled();
        }

        void unlocked(byte[] vmk, byte[] fingerprint) {
            if (!isActive() || !terminal.compareAndSet(false, true)) {
                CryptoEngine.wipe(vmk);
                CryptoEngine.wipe(fingerprint);
                if (!terminal.get()) cancel();
                return;
            }
            activity.removeForegroundLossObserver(foregroundObserver);
            clearPhase();
            callback.onUnlocked(vmk, fingerprint);
        }
    }

    private UnlockCoordinator() {}

    static void unlock(SecureActivity activity, String reason, Callback callback) {
        unlock(activity, ignored -> reason, callback);
    }

    /** Passphrase-only route for settings that change biometric trust policy itself. */
    static void unlockWithPassphraseOnly(SecureActivity activity, String reason,
                                         Callback callback) {
        UnlockSession session = new UnlockSession(activity, callback);
        if (!session.begin()) return;
        byte[] fingerprint;
        String displayedReason;
        try {
            AuthenticatedSnapshot snapshot = new VaultStore(activity).readLocked(
                    current -> new AuthenticatedSnapshot(current,
                            VaultStore.snapshotFingerprint(current),
                            PassphrasePromptText.actionReason(reason)));
            fingerprint = snapshot.fingerprint;
            snapshot.fingerprint = null;
            displayedReason = snapshot.reason;
        } catch (VaultException exception) {
            if (session.isActive()) Ui.showError(activity, exception.getMessage());
            session.cancel();
            return;
        }
        promptPassphrase(activity, displayedReason, PassphrasePromptText.Route.DIRECT,
                fingerprint, session);
    }

    static ReasonResolver entryReason(String entryId, EntryAction action) {
        return state -> {
            VaultState.Entry entry = state.findEntry(entryId);
            if (entry == null) throw new VaultException("Entry no longer exists");
            return switch (action) {
                case EDIT -> AuthorizationReason.editCommand(entry.title);
                case RUN -> AuthorizationReason.runCommand(entry.title);
                case TRUST_AND_RUN -> AuthorizationReason.trustAndRun(entry.title);
                case DELETE -> AuthorizationReason.deleteCommand(entry.title);
            };
        };
    }

    static ReasonResolver termuxTrustReason() {
        return state -> AuthorizationReason.trustTermux(
                !state.trustedTermuxCertificates.isEmpty());
    }

    static void unlock(SecureActivity activity, ReasonResolver reasonResolver,
                       Callback callback) {
        UnlockSession session = new UnlockSession(activity, callback);
        if (!session.begin()) return;
        AuthenticatedSnapshot snapshot;
        try {
            snapshot = new VaultStore(activity).readLocked(current -> new AuthenticatedSnapshot(
                    current, VaultStore.snapshotFingerprint(current),
                    PassphrasePromptText.actionReason(reasonResolver.resolve(current))));
        } catch (VaultException exception) {
            if (session.isActive()) Ui.showError(activity, exception.getMessage());
            session.cancel();
            return;
        }

        VaultState state = snapshot.state;
        String reason = snapshot.reason;

        if (state.bioVmkIv == null || state.bioVmkCiphertext == null) {
            byte[] authenticatedFingerprint = snapshot.fingerprint;
            snapshot.fingerprint = null;
            promptPassphrase(activity, reason, PassphrasePromptText.Route.DIRECT,
                    authenticatedFingerprint, session);
            return;
        }
        if (!BiometricKeyManager.hasKey()) {
            byte[] authenticatedFingerprint = snapshot.fingerprint;
            snapshot.fingerprint = null;
            promptPassphrase(activity, reason,
                    PassphrasePromptText.Route.BIOMETRIC_UNAVAILABLE,
                    authenticatedFingerprint, session);
            return;
        }

        byte[] iv = null;
        byte[] ciphertext = null;
        try {
            iv = CryptoEngine.fromBase64(state.bioVmkIv);
            ciphertext = CryptoEngine.fromBase64(state.bioVmkCiphertext);
            BiometricKeyManager.ManagedKey managedKey = BiometricKeyManager.loadKey();
            Cipher cipher = BiometricKeyManager.newDecryptCipher(managedKey.key, iv);
            reviewBiometricPolicyIfNeeded(activity, state, snapshot.fingerprint, reason, cipher,
                    ciphertext, managedKey.policyReport, session);
            snapshot.fingerprint = null;
            ciphertext = null;
        } catch (KeyPermanentlyInvalidatedException exception) {
            CryptoEngine.wipe(ciphertext);
            byte[] authenticatedFingerprint = snapshot.fingerprint;
            snapshot.fingerprint = null;
            promptPassphrase(activity, reason,
                    PassphrasePromptText.Route.BIOMETRIC_INVALIDATED,
                    authenticatedFingerprint, session);
        } catch (Exception exception) {
            CryptoEngine.wipe(ciphertext);
            byte[] authenticatedFingerprint = snapshot.fingerprint;
            snapshot.fingerprint = null;
            promptPassphrase(activity, reason,
                    BiometricKeyManager.isPermanentlyInvalidated(exception)
                            ? PassphrasePromptText.Route.BIOMETRIC_INVALIDATED
                            : PassphrasePromptText.Route.BIOMETRIC_UNAVAILABLE,
                    authenticatedFingerprint, session);
        } finally {
            CryptoEngine.wipe(iv);
            CryptoEngine.wipe(snapshot.fingerprint);
        }
    }

    private static void reviewBiometricPolicyIfNeeded(
            SecureActivity activity, VaultState state, byte[] authenticatedFingerprint,
            String reason, Cipher cipher, byte[] ciphertext,
            BiometricKeyPolicy.PolicyReport policyReport, UnlockSession session) {
        if (!policyReport.hasDeviations()
                || policyReport.isAcknowledgedBy(state.bioPolicyAcknowledgements)) {
            promptBiometricDecrypt(activity, state, authenticatedFingerprint, reason, cipher,
                    ciphertext, session);
            return;
        }
        if (!session.isActive()) {
            CryptoEngine.wipe(ciphertext);
            CryptoEngine.wipe(authenticatedFingerprint);
            session.cancel();
            return;
        }

        AtomicBoolean completed = new AtomicBoolean(false);
        AlertDialog dialog = BiometricPolicyWarningDialog.create(activity, policyReport, reason,
                "Termux Vault will use the vault passphrase for this action. Review biometric "
                        + "unlock in Settings if you want to accept these device-specific findings.",
                "Use vault passphrase", "Cancel",
                new BiometricPolicyWarningDialog.Callback() {
                    @Override
                    public void onContinue() {
                        if (!completed.compareAndSet(false, true)) return;
                        session.clearPhase();
                        CryptoEngine.wipe(ciphertext);
                        promptPassphrase(activity, reason,
                                PassphrasePromptText.Route.BIOMETRIC_CHOSEN,
                                authenticatedFingerprint, session);
                    }

                    @Override
                    public void onDecline() {
                        if (!completed.compareAndSet(false, true)) return;
                        session.cancel();
                    }

                    @Override
                    public void onCancel() {
                        onDecline();
                    }
                });
        session.setPhase(null, dialog, () -> {
            CryptoEngine.wipe(ciphertext);
            CryptoEngine.wipe(authenticatedFingerprint);
        });
        if (session.isActive()) dialog.show();
    }

    private static void promptBiometricDecrypt(SecureActivity activity, VaultState state,
                                               byte[] authenticatedFingerprint, String reason,
                                               Cipher cipher, byte[] ciphertext,
                                               UnlockSession session) {
        if (!session.isActive()) {
            CryptoEngine.wipe(ciphertext);
            CryptoEngine.wipe(authenticatedFingerprint);
            session.cancel();
            return;
        }
        AtomicBoolean completed = new AtomicBoolean(false);
        CancellationSignal cancellation = new CancellationSignal();
        BiometricPrompt prompt = new BiometricPrompt.Builder(activity)
                .setTitle("Unlock protected command")
                .setSubtitle(reason)
                .setConfirmationRequired(true)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButton("Use vault passphrase", activity.getMainExecutor(), (dialog, which) -> {
                    if (completed.compareAndSet(false, true)) {
                        session.clearPhase();
                        CryptoEngine.wipe(ciphertext);
                        promptPassphrase(activity, reason,
                                PassphrasePromptText.Route.BIOMETRIC_CHOSEN,
                                authenticatedFingerprint, session);
                    }
                })
                .build();

        session.setPhase(cancellation, null, () -> {
            CryptoEngine.wipe(ciphertext);
            CryptoEngine.wipe(authenticatedFingerprint);
        });
        if (!session.isActive()) return;
        try {
            prompt.authenticate(new BiometricPrompt.CryptoObject(cipher), cancellation,
                    activity.getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                        if (!completed.compareAndSet(false, true)) return;
                        session.clearPhase();
                        if (!session.isActive()) {
                            CryptoEngine.wipe(ciphertext);
                            CryptoEngine.wipe(authenticatedFingerprint);
                            session.cancel();
                            return;
                        }
                        try {
                            Cipher authenticated = result.getCryptoObject() == null
                                    ? null : result.getCryptoObject().getCipher();
                            if (authenticated == null) throw new GeneralSecurityException("Missing authenticated cipher");
                            byte[] vmk = BiometricKeyManager.finishAuthenticatedDecryption(
                                    authenticated, ciphertext);
                            CryptoEngine.wipe(ciphertext);
                            byte[] callbackFingerprint = null;
                            try {
                                if (vmk.length != CryptoEngine.KEY_BYTES) {
                                    throw new GeneralSecurityException("Invalid vault key");
                                }
                                try {
                                    new VaultStore(activity).readIfUnchanged(
                                            authenticatedFingerprint, current -> {
                                        if (state.bioVmkIv == null
                                                || !state.bioVmkIv.equals(current.bioVmkIv)
                                                || state.bioVmkCiphertext == null
                                                || !state.bioVmkCiphertext.equals(
                                                        current.bioVmkCiphertext)) {
                                            throw new VaultException("Biometric wrapper changed");
                                        }
                                        return null;
                                    });
                                } catch (VaultException exception) {
                                    throw new SnapshotVerificationException(exception);
                                }
                                callbackFingerprint = authenticatedFingerprint.clone();
                                session.unlocked(vmk, callbackFingerprint);
                                vmk = null;
                                callbackFingerprint = null;
                                CryptoEngine.wipe(authenticatedFingerprint);
                            } finally {
                                CryptoEngine.wipe(vmk);
                                CryptoEngine.wipe(callbackFingerprint);
                            }
                        } catch (Exception exception) {
                            CryptoEngine.wipe(ciphertext);
                            if (exception instanceof SnapshotVerificationException) {
                                CryptoEngine.wipe(authenticatedFingerprint);
                                if (session.isActive()) {
                                    Ui.showError(activity,
                                            "The vault changed or could not be verified after "
                                                    + "biometric authorization. Review the current "
                                                    + "state and try again.");
                                }
                                session.cancel();
                            } else {
                                promptPassphrase(activity, reason,
                                        BiometricKeyManager.isPermanentlyInvalidated(exception)
                                                ? PassphrasePromptText.Route.BIOMETRIC_INVALIDATED
                                                : PassphrasePromptText.Route.BIOMETRIC_UNAVAILABLE,
                                        authenticatedFingerprint, session);
                            }
                        }
                    }

                    @Override
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        if (!completed.compareAndSet(false, true)) return;
                        session.clearPhase();
                        CryptoEngine.wipe(ciphertext);
                        if (errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED
                                || errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED) {
                            CryptoEngine.wipe(authenticatedFingerprint);
                            session.cancel();
                        } else if (errorCode == BiometricPrompt.BIOMETRIC_ERROR_NO_BIOMETRICS
                                || errorCode == BiometricPrompt.BIOMETRIC_ERROR_HW_NOT_PRESENT
                                || errorCode == BiometricPrompt.BIOMETRIC_ERROR_NOT_ENABLED_FOR_APPS) {
                            promptPassphrase(activity, reason,
                                    PassphrasePromptText.Route.BIOMETRIC_UNAVAILABLE,
                                    authenticatedFingerprint, session);
                        } else {
                            promptPassphrase(activity, reason,
                                    PassphrasePromptText.Route.BIOMETRIC_FAILED,
                                    authenticatedFingerprint, session);
                        }
                    }
                });
        } catch (RuntimeException exception) {
            if (!completed.compareAndSet(false, true)) return;
            session.clearPhase();
            CryptoEngine.wipe(ciphertext);
            promptPassphrase(activity, reason,
                    PassphrasePromptText.Route.BIOMETRIC_UNAVAILABLE,
                    authenticatedFingerprint, session);
        }
    }

    private static void promptPassphrase(SecureActivity activity, String reason,
                                         PassphrasePromptText.Route route,
                                         byte[] authenticatedFingerprint,
                                         UnlockSession session) {
        if (authenticatedFingerprint == null
                || authenticatedFingerprint.length != CryptoEngine.KEY_BYTES
                || !session.isActive()) {
            CryptoEngine.wipe(authenticatedFingerprint);
            session.cancel();
            return;
        }
        LinearLayout body = Ui.page(activity);
        body.setPadding(Ui.dp(activity, 20), Ui.dp(activity, 8), Ui.dp(activity, 20), 0);
        TextView actionLabel = Ui.text(activity, "Action to authorize", 13, Ui.MUTED);
        actionLabel.setAccessibilityHeading(true);
        body.addView(actionLabel, Ui.matchWrap());
        TextView action = Ui.text(activity, PassphrasePromptText.actionReason(reason),
                18, Ui.TEXT);
        action.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        body.addView(action, Ui.matchWrap());
        Ui.addSpace(body, 12);
        TextView explanation = Ui.text(activity, PassphrasePromptText.explanation(route),
                14, Ui.MUTED);
        body.addView(explanation, Ui.matchWrap());
        Ui.addSpace(body, 8);
        PasswordInput passphraseInput = new PasswordInput(activity, "Vault passphrase");
        EditText passphrase = passphraseInput.editText();
        passphraseInput.setImeOptions(EditorInfo.IME_ACTION_DONE
                | EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                | EditorInfo.IME_FLAG_NO_EXTRACT_UI);
        body.addView(passphraseInput, Ui.matchWrap());
        TextView error = Ui.text(activity, "", 13, Ui.DANGER);
        body.addView(error, Ui.matchWrap());

        AtomicBoolean finished = new AtomicBoolean(false);
        AlertDialog dialog = Ui.createSecure(new AlertDialog.Builder(activity)
                .setTitle("Vault passphrase")
                .setView(body)
                .setPositiveButton("Unlock", null)
                .setNegativeButton("Cancel", (ignored, which) -> {
                    if (finished.compareAndSet(false, true)) session.cancel();
                })
                .setOnCancelListener(ignored -> {
                    if (finished.compareAndSet(false, true)) session.cancel();
                })
        );
        session.setPhase(null, dialog,
                () -> CryptoEngine.wipe(authenticatedFingerprint));
        if (!session.isActive()) return;
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(view -> {
            char[] chars = Ui.readChars(passphrase);
            Ui.clear(passphrase);
            if (chars.length == 0) {
                CryptoEngine.wipe(chars);
                error.setText("Passphrase is incorrect.");
                return;
            }
            byte[] attemptFingerprint = authenticatedFingerprint.clone();
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);
            error.setText("Unlocking…");
            new Thread(() -> {
                UnlockedVault unlockedVault = null;
                VaultException failure = null;
                try {
                    // Compare and derive under the same lock. A fallback prompt can authorize only
                    // the exact vault snapshot and action context displayed when unlock began.
                    unlockedVault = new VaultStore(activity).readIfUnchanged(
                            attemptFingerprint, current -> {
                        byte[] vmk = null;
                        byte[] fingerprint = null;
                        try {
                            vmk = VaultService.unlockWithPassphrase(current, chars);
                            fingerprint = attemptFingerprint.clone();
                            UnlockedVault result = new UnlockedVault(vmk, fingerprint);
                            vmk = null;
                            fingerprint = null;
                            return result;
                        } finally {
                            CryptoEngine.wipe(vmk);
                            CryptoEngine.wipe(fingerprint);
                        }
                    });
                } catch (VaultException exception) {
                    failure = exception;
                } finally {
                    CryptoEngine.wipe(chars);
                    CryptoEngine.wipe(attemptFingerprint);
                }
                UnlockedVault unlocked = unlockedVault;
                VaultException finalFailure = failure;
                activity.runOnUiThread(() -> {
                    if (!session.isActive() || finished.get()) {
                        if (unlocked != null) unlocked.wipe();
                        session.cancel();
                        return;
                    }
                    if (finalFailure != null) {
                        if (finalFailure.isAuthenticationFailure()) {
                            error.setText("Passphrase is incorrect.");
                            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(true);
                        } else {
                            error.setText(finalFailure.isStateChanged()
                                    ? "Authorization expired because the vault changed. Close this "
                                            + "prompt and try the action again."
                                    : "The vault could not be verified. Close this prompt and try "
                                            + "the action again.");
                            dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setText("Close");
                        }
                        return;
                    }
                    finished.set(true);
                    session.clearPhase();
                    CryptoEngine.wipe(authenticatedFingerprint);
                    dialog.dismiss();
                    byte[] vmk = unlocked.vmk;
                    byte[] fingerprint = unlocked.fingerprint;
                    unlocked.vmk = null;
                    unlocked.fingerprint = null;
                    session.unlocked(vmk, fingerprint);
                });
            }, "vault-kdf").start();
        }));
        dialog.setOnDismissListener(ignored -> Ui.clear(passphrase));
        dialog.show();
    }
}
