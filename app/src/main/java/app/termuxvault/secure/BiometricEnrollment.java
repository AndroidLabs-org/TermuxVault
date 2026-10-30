package app.termuxvault.secure;

import android.app.AlertDialog;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.CancellationSignal;

import java.security.GeneralSecurityException;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Cipher;

final class BiometricEnrollment {
    enum Failure {
        INVALID_VAULT_KEY("The vault key was unavailable."),
        INVALID_AUTHORIZATION("The authenticated vault snapshot was unavailable."),
        CLASS_2_ONLY(BiometricAvailability.message(BiometricAvailability.Status.CLASS_2_ONLY)),
        STRONG_BIOMETRIC_NOT_ENROLLED(
                BiometricAvailability.message(BiometricAvailability.Status.NOT_ENROLLED)),
        STRONG_BIOMETRIC_TEMPORARY(
                BiometricAvailability.message(
                        BiometricAvailability.Status.TEMPORARILY_UNAVAILABLE)),
        STRONG_BIOMETRIC_SECURITY_UPDATE(
                BiometricAvailability.message(
                        BiometricAvailability.Status.SECURITY_UPDATE_REQUIRED)),
        STRONG_BIOMETRIC_DISABLED(
                BiometricAvailability.message(BiometricAvailability.Status.DISABLED_FOR_APPS)),
        STRONG_BIOMETRIC_NO_HARDWARE(
                BiometricAvailability.message(BiometricAvailability.Status.NO_HARDWARE)),
        STRONG_BIOMETRIC_UNSUPPORTED(
                BiometricAvailability.message(BiometricAvailability.Status.UNSUPPORTED)),
        STRONG_BIOMETRIC_UNAVAILABLE(
                BiometricAvailability.message(BiometricAvailability.Status.UNKNOWN)),
        REQUEST_BUSY("Another biometric request is already active."),
        KEY_PREPARATION("Android could not prepare the cryptographic key required for biometric "
                + "unlock."),
        PROMPT("The Android biometric prompt could not be completed."),
        HARDWARE_TEMPORARY("Biometric hardware is temporarily unavailable. Try again shortly."),
        SENSOR_LOCKED("The biometric sensor is locked. Unlock Android normally, then try again."),
        WRAP_STORAGE("The authenticated biometric vault key could not be stored.");

        final String message;

        Failure(String message) {
            this.message = message;
        }
    }

    interface Callback {
        void onEnabled();
        void onCancelled();
        void onUnavailable(Failure failure);
    }

    private static final AtomicBoolean ACTIVE = new AtomicBoolean(false);

    private static final class EnrollmentSession {
        private enum Phase {
            PREPARING,
            REVIEWING,
            PROMPT,
            PERSISTING,
            TERMINAL
        }

        private final SecureActivity activity;
        private final byte[] vmk;
        private final byte[] vaultFingerprint;
        private final AtomicBoolean cancelled = new AtomicBoolean(false);
        private final Runnable foregroundObserver = this::cancelForForegroundLoss;
        private volatile Phase phase = Phase.PREPARING;
        private CancellationSignal cancellationSignal;
        private AlertDialog reviewDialog;
        private Runnable promptAbort;

        EnrollmentSession(SecureActivity activity, byte[] vmk, byte[] vaultFingerprint) {
            this.activity = activity;
            this.vmk = vmk;
            this.vaultFingerprint = vaultFingerprint;
        }

        boolean begin() {
            return activity.addForegroundLossObserver(foregroundObserver);
        }

        boolean isCancelled() {
            return cancelled.get() || !activity.isSecureSessionActive();
        }

        void enterPrompt(CancellationSignal signal, Runnable abort) {
            phase = Phase.PROMPT;
            cancellationSignal = signal;
            reviewDialog = null;
            promptAbort = abort;
            if (isCancelled()) cancelForForegroundLoss();
        }

        void enterReview(AlertDialog dialog, Runnable abort) {
            phase = Phase.REVIEWING;
            cancellationSignal = null;
            reviewDialog = dialog;
            promptAbort = abort;
            if (isCancelled()) cancelForForegroundLoss();
        }

        void leaveReview() {
            reviewDialog = null;
            promptAbort = null;
        }

        boolean beginPersisting() {
            cancellationSignal = null;
            reviewDialog = null;
            promptAbort = null;
            if (isCancelled()) return false;
            phase = Phase.PERSISTING;
            return !isCancelled();
        }

        void finish() {
            phase = Phase.TERMINAL;
            cancellationSignal = null;
            reviewDialog = null;
            promptAbort = null;
            activity.removeForegroundLossObserver(foregroundObserver);
        }

        private void cancelForForegroundLoss() {
            if (!cancelled.compareAndSet(false, true)) return;
            CancellationSignal signal = cancellationSignal;
            AlertDialog dialog = reviewDialog;
            Runnable abort = promptAbort;
            if (signal != null && !signal.isCanceled()) signal.cancel();
            if (dialog != null && dialog.isShowing()) dialog.dismiss();
            if (phase != Phase.PERSISTING) {
                CryptoEngine.wipe(vmk);
                CryptoEngine.wipe(vaultFingerprint);
            }
            if (abort != null) abort.run();
        }
    }

    private BiometricEnrollment() {}

    static boolean canEnroll(SecureActivity activity) {
        return BiometricAvailability.status(activity)
                == BiometricAvailability.Status.STRONG_AVAILABLE;
    }

    /** Takes ownership of both arrays and wipes them on every terminal path. */
    static void enroll(SecureActivity activity, byte[] vmk, byte[] vaultFingerprint,
                       Callback callback) {
        if (vmk == null || vmk.length != CryptoEngine.KEY_BYTES) {
            CryptoEngine.wipe(vmk);
            CryptoEngine.wipe(vaultFingerprint);
            callback.onUnavailable(Failure.INVALID_VAULT_KEY);
            return;
        }
        if (vaultFingerprint == null || vaultFingerprint.length != CryptoEngine.KEY_BYTES) {
            CryptoEngine.wipe(vmk);
            CryptoEngine.wipe(vaultFingerprint);
            callback.onUnavailable(Failure.INVALID_AUTHORIZATION);
            return;
        }
        BiometricAvailability.Status availability = BiometricAvailability.status(activity);
        if (availability != BiometricAvailability.Status.STRONG_AVAILABLE) {
            CryptoEngine.wipe(vmk);
            CryptoEngine.wipe(vaultFingerprint);
            callback.onUnavailable(failureFor(availability));
            return;
        }
        if (!ACTIVE.compareAndSet(false, true)) {
            CryptoEngine.wipe(vmk);
            CryptoEngine.wipe(vaultFingerprint);
            callback.onUnavailable(Failure.REQUEST_BUSY);
            return;
        }

        EnrollmentSession session = new EnrollmentSession(activity, vmk, vaultFingerprint);
        if (!session.begin()) {
            CryptoEngine.wipe(vmk);
            CryptoEngine.wipe(vaultFingerprint);
            ACTIVE.set(false);
            return;
        }

        new Thread(() -> {
            Cipher cipher = null;
            BiometricKeyPolicy.PolicyReport policyReport = null;
            try {
                BiometricKeyManager.ManagedKey managedKey =
                        BiometricKeyManager.createFreshKey();
                cipher = BiometricKeyManager.newEncryptCipher(managedKey.key);
                policyReport = managedKey.policyReport;
            } catch (Exception ignored) {
                discardKey();
            }
            Cipher prepared = cipher;
            BiometricKeyPolicy.PolicyReport preparedReport = policyReport;
            activity.runOnUiThread(() -> {
                if (session.isCancelled() || !activity.isSecureSessionActive()) {
                    finishSilently(vmk, vaultFingerprint, session);
                } else if (prepared == null || preparedReport == null) {
                    finishUnavailable(vmk, vaultFingerprint, session, callback,
                            Failure.KEY_PREPARATION);
                } else if (preparedReport.hasDeviations()) {
                    showPolicyWarning(activity, prepared, preparedReport, vmk,
                            vaultFingerprint, session, callback);
                } else {
                    showPrompt(activity, prepared, preparedReport, vmk, vaultFingerprint,
                            session, callback);
                }
            });
        }, "vault-biometric-key").start();
    }

    private static void showPolicyWarning(SecureActivity activity, Cipher cipher,
                                          BiometricKeyPolicy.PolicyReport policyReport,
                                          byte[] vmk, byte[] vaultFingerprint,
                                          EnrollmentSession session, Callback callback) {
        AtomicBoolean completed = new AtomicBoolean(false);
        AlertDialog dialog = BiometricPolicyWarningDialog.create(activity, policyReport,
                AuthorizationReason.enableBiometric(), null, "Enable biometric unlock",
                "Keep passphrase only", new BiometricPolicyWarningDialog.Callback() {
                    @Override
                    public void onContinue() {
                        if (!completed.compareAndSet(false, true)) return;
                        session.leaveReview();
                        if (session.isCancelled() || !activity.isSecureSessionActive()) {
                            finishSilently(vmk, vaultFingerprint, session);
                        } else {
                            showPrompt(activity, cipher, policyReport, vmk, vaultFingerprint,
                                    session, callback);
                        }
                    }

                    @Override
                    public void onDecline() {
                        if (!completed.compareAndSet(false, true)) return;
                        session.leaveReview();
                        finishCancelled(vmk, vaultFingerprint, session, callback);
                    }

                    @Override
                    public void onCancel() {
                        onDecline();
                    }
                });
        session.enterReview(dialog, () -> {
            if (completed.compareAndSet(false, true)) {
                finishSilently(vmk, vaultFingerprint, session);
            }
        });
        if (!completed.get()) dialog.show();
    }

    private static void showPrompt(SecureActivity activity, Cipher cipher,
                                   BiometricKeyPolicy.PolicyReport policyReport, byte[] vmk,
                                   byte[] vaultFingerprint, EnrollmentSession session,
                                   Callback callback) {
        AtomicBoolean completed = new AtomicBoolean(false);
        try {
            CancellationSignal cancellation = new CancellationSignal();
            BiometricPrompt prompt = new BiometricPrompt.Builder(activity)
                    .setTitle("Enable biometric unlock")
                    .setSubtitle(BiometricEnrollmentUi.PROMPT_SUBTITLE)
                    .setConfirmationRequired(true)
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setNegativeButton("Not now", activity.getMainExecutor(), (dialog, which) -> {
                        if (completed.compareAndSet(false, true)) {
                            if (session.isCancelled() || !activity.isSecureSessionActive()) {
                                finishSilently(vmk, vaultFingerprint, session);
                            } else {
                                finishCancelled(vmk, vaultFingerprint, session, callback);
                            }
                        }
                    })
                    .build();
            session.enterPrompt(cancellation, () -> {
                if (completed.compareAndSet(false, true)) {
                    finishSilently(vmk, vaultFingerprint, session);
                }
            });
            if (completed.get()) return;
            prompt.authenticate(new BiometricPrompt.CryptoObject(cipher), cancellation,
                    activity.getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                        @Override
                        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                            if (!completed.compareAndSet(false, true)) return;
                            if (!session.beginPersisting()) {
                                finishSilently(vmk, vaultFingerprint, session);
                                return;
                            }
                            Cipher authenticated = result.getCryptoObject() == null
                                    ? null : result.getCryptoObject().getCipher();
                            if (authenticated == null) {
                                finishUnavailable(vmk, vaultFingerprint, session, callback,
                                        Failure.PROMPT);
                                return;
                            }
                            persistWrap(activity, authenticated, policyReport, vmk,
                                    vaultFingerprint, session, callback);
                        }

                        @Override
                        public void onAuthenticationError(int errorCode, CharSequence errString) {
                            if (!completed.compareAndSet(false, true)) return;
                            if (session.isCancelled() || !activity.isSecureSessionActive()) {
                                finishSilently(vmk, vaultFingerprint, session);
                            } else if (errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED
                                    || errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED) {
                                finishCancelled(vmk, vaultFingerprint, session, callback);
                            } else if (errorCode == BiometricPrompt.BIOMETRIC_ERROR_HW_UNAVAILABLE) {
                                finishUnavailable(vmk, vaultFingerprint, session, callback,
                                        Failure.HARDWARE_TEMPORARY);
                            } else if (errorCode == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT
                                    || errorCode == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT) {
                                finishUnavailable(vmk, vaultFingerprint, session, callback,
                                        Failure.SENSOR_LOCKED);
                            } else {
                                finishUnavailable(vmk, vaultFingerprint, session, callback,
                                        Failure.PROMPT);
                            }
                        }
                    });
        } catch (Exception ignored) {
            if (completed.compareAndSet(false, true)) {
                if (session.isCancelled() || !activity.isSecureSessionActive()) {
                    finishSilently(vmk, vaultFingerprint, session);
                } else {
                    finishUnavailable(vmk, vaultFingerprint, session, callback, Failure.PROMPT);
                }
            }
        }
    }

    private static void persistWrap(SecureActivity activity, Cipher cipher,
                                    BiometricKeyPolicy.PolicyReport policyReport, byte[] vmk,
                                    byte[] vaultFingerprint, EnrollmentSession session,
                                    Callback callback) {
        new Thread(() -> {
            byte[] iv = null;
            byte[] ciphertext = null;
            boolean saved = false;
            try {
                if (session.isCancelled()) throw new GeneralSecurityException("Cancelled");
                ciphertext = BiometricKeyManager.finishAuthenticatedEncryption(cipher, vmk);
                iv = cipher.getIV();
                if (iv == null || iv.length != CryptoEngine.GCM_IV_BYTES
                        || ciphertext.length != CryptoEngine.KEY_BYTES + 16) {
                    throw new GeneralSecurityException("Invalid biometric wrapping result");
                }
                String encodedIv = CryptoEngine.toBase64(iv);
                String encodedCiphertext = CryptoEngine.toBase64(ciphertext);
                if (session.isCancelled()) throw new GeneralSecurityException("Cancelled");
                new VaultStore(activity.getApplicationContext()).mutateIfUnchanged(
                        vaultFingerprint, state -> {
                    if (session.isCancelled()) throw new VaultException("Cancelled");
                    state.bioVmkIv = encodedIv;
                    state.bioVmkCiphertext = encodedCiphertext;
                    state.bioPolicyAcknowledgements.clear();
                    policyReport.mergeAcknowledgementsInto(
                            state.bioPolicyAcknowledgements,
                            VaultStore.MAX_BIOMETRIC_POLICY_ACKNOWLEDGEMENTS);
                });
                saved = true;
            } catch (Exception ignored) {
                if (!saved) discardKey();
            } finally {
                CryptoEngine.wipe(iv);
                CryptoEngine.wipe(ciphertext);
                CryptoEngine.wipe(vmk);
                CryptoEngine.wipe(vaultFingerprint);
                ACTIVE.set(false);
            }
            boolean completed = saved;
            activity.runOnUiThread(() -> {
                session.finish();
                if (session.isCancelled() || !activity.isSecureSessionActive()) return;
                if (completed) callback.onEnabled();
                else callback.onUnavailable(Failure.WRAP_STORAGE);
            });
        }, "vault-biometric-wrap").start();
    }

    private static void finishCancelled(byte[] vmk, byte[] vaultFingerprint,
                                        EnrollmentSession session, Callback callback) {
        discardKey();
        CryptoEngine.wipe(vmk);
        CryptoEngine.wipe(vaultFingerprint);
        ACTIVE.set(false);
        session.finish();
        callback.onCancelled();
    }

    private static void finishUnavailable(byte[] vmk, byte[] vaultFingerprint,
                                          EnrollmentSession session, Callback callback,
                                          Failure failure) {
        discardKey();
        CryptoEngine.wipe(vmk);
        CryptoEngine.wipe(vaultFingerprint);
        ACTIVE.set(false);
        session.finish();
        callback.onUnavailable(failure);
    }

    private static void finishSilently(byte[] vmk, byte[] vaultFingerprint,
                                       EnrollmentSession session) {
        discardKey();
        CryptoEngine.wipe(vmk);
        CryptoEngine.wipe(vaultFingerprint);
        ACTIVE.set(false);
        session.finish();
    }

    private static void discardKey() {
        try {
            BiometricKeyManager.deleteKey();
        } catch (GeneralSecurityException ignored) {
        }
    }

    private static Failure failureFor(BiometricAvailability.Status status) {
        return switch (status) {
            case CLASS_2_ONLY -> Failure.CLASS_2_ONLY;
            case NOT_ENROLLED -> Failure.STRONG_BIOMETRIC_NOT_ENROLLED;
            case TEMPORARILY_UNAVAILABLE -> Failure.STRONG_BIOMETRIC_TEMPORARY;
            case SECURITY_UPDATE_REQUIRED -> Failure.STRONG_BIOMETRIC_SECURITY_UPDATE;
            case DISABLED_FOR_APPS -> Failure.STRONG_BIOMETRIC_DISABLED;
            case NO_HARDWARE -> Failure.STRONG_BIOMETRIC_NO_HARDWARE;
            case UNSUPPORTED -> Failure.STRONG_BIOMETRIC_UNSUPPORTED;
            case UNKNOWN, STRONG_AVAILABLE -> Failure.STRONG_BIOMETRIC_UNAVAILABLE;
        };
    }
}
