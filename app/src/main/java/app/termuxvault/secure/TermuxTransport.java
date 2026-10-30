package app.termuxvault.secure;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

final class TermuxTransport {
    interface Callback {
        void onHandoffComplete();
        void onHandoffFailed(String message, boolean offerTermuxAppInfo);
    }

    private static final int HANDOFF_TIMEOUT_MS = 12_000;
    static final String HANDOFF_TIMEOUT_MESSAGE =
            "Termux did not complete the one-time handoff within 12 seconds.\n\n"
                    + "If Termux did not open in the foreground, Android may have blocked it. "
                    + "Check that Display over other apps is enabled for Termux.\n\n"
                    + "If Termux opened, startup or superuser approval may have taken too long. "
                    + "After checking the applicable cause, return to Termux Vault and try again.";
    static final int PRE_AUTH_TIMEOUT_MS = 650;
    private static final int MAX_HANDSHAKE_BYTES = 65;

    enum HandoffResult {
        DELIVERED,
        SYNTAX_REJECTED,
        EXPIRED
    }

    private TermuxTransport() {}

    static void launch(Activity activity, String displayTitle, byte[] command,
                       boolean pauseAfterRun, boolean hideTerminalOutput,
                       CompletionStore.Request completion,
                       Callback callback) {
        AtomicBoolean callbackDelivered = new AtomicBoolean(false);
        Callback once = new Callback() {
            @Override
            public void onHandoffComplete() {
                if (callbackDelivered.compareAndSet(false, true)) callback.onHandoffComplete();
            }

            @Override
            public void onHandoffFailed(String message, boolean offerTermuxAppInfo) {
                if (callbackDelivered.compareAndSet(false, true)) {
                    CompletionStore.cancel(activity, completion);
                    callback.onHandoffFailed(message, offerTermuxAppInfo);
                }
            }
        };
        if (command == null || command.length == 0 || command.length > VaultService.MAX_COMMAND_BYTES) {
            CryptoEngine.wipe(command);
            once.onHandoffFailed("Command data is invalid.", false);
            return;
        }
        try {
            VaultState state = new VaultStore(activity).load();
            if (!TermuxIdentity.read(activity).matches(state.trustedTermuxCertificates)) {
                CryptoEngine.wipe(command);
                once.onHandoffFailed("Termux identity is no longer trusted.", false);
                return;
            }
        } catch (Exception exception) {
            CryptoEngine.wipe(command);
            once.onHandoffFailed("Termux identity could not be verified.", false);
            return;
        }
        ServerSocket server;
        byte[] clientTokenBytes = CryptoEngine.randomBytes(32);
        byte[] serverTokenBytes = CryptoEngine.randomBytes(32);
        String clientToken = hex(clientTokenBytes);
        String serverToken = hex(serverTokenBytes);
        CryptoEngine.wipe(clientTokenBytes);
        CryptoEngine.wipe(serverTokenBytes);
        try {
            server = new ServerSocket();
            server.setReuseAddress(false);
            server.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 4);
        } catch (IOException exception) {
            CryptoEngine.wipe(command);
            once.onHandoffFailed("The local secure handoff could not be opened.", false);
            return;
        }

        Handler main = new Handler(Looper.getMainLooper());
        int port = server.getLocalPort();
        long deadlineNanos = System.nanoTime() +
                TimeUnit.MILLISECONDS.toNanos(HANDOFF_TIMEOUT_MS);
        new Thread(() -> serve(server, clientToken, serverToken, command, deadlineNanos, main, once),
                "termux-vault-handoff").start();

        Intent run = new Intent(ACTION_SAFE());
        run.setComponent(new ComponentName(TermuxIdentity.PACKAGE_NAME, TermuxIdentity.RUN_SERVICE_NAME));
        run.addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES);
        run.putExtra(TermuxContract.EXTRA_PATH, "$PREFIX/bin/bash");
        run.putExtra(TermuxContract.EXTRA_ARGUMENTS, new String[]{
                "--noprofile", "--norc", "-p", "-c", ShellBootstrap.SCRIPT,
                "termux-vault", Integer.toString(port), clientToken, serverToken,
                pauseAfterRun ? "1" : "0",
                completion == null ? "-" : completion.id,
                completion == null ? "-" : completion.token,
                activity.getPackageName(), CompletionReceiver.class.getName(),
                sanitizeDisplayTitle(displayTitle), hideTerminalOutput ? "1" : "0"
        });
        // Deliberately omit WORKDIR. Termux then selects its own profile-specific home directory.
        run.putExtra(TermuxContract.EXTRA_BACKGROUND, false);
        // Termux expects this integer-valued setting as a String extra.
        run.putExtra(TermuxContract.EXTRA_BACKGROUND_CUSTOM_LOG_LEVEL, "0");
        run.putExtra(TermuxContract.EXTRA_SESSION_ACTION,
                TermuxContract.SESSION_ACTION_SWITCH_TO_NEW_DONT_OPEN);

        // Ask Termux to create and select the session without having its background service launch
        // an Activity. Vault is already a visible Activity, so it immediately brings Termux forward
        // itself. This avoids Android's background-Activity-start path (and its usual overlay-access
        // requirement) while still letting Termux attach and size the new terminal before the
        // bootstrap performs the authenticated handoff.
        if (startRunService(activity, run)) {
            openTermux(activity);
            return;
        }

        closeQuietly(server);
        CryptoEngine.wipe(command);
        once.onHandoffFailed(
                "Termux did not accept the foreground command request. Open Termux and try again.",
                true);
    }

    private static boolean startRunService(Activity activity, Intent run) {
        try {
            return activity.startForegroundService(run) != null;
        } catch (RuntimeException exception) {
            return false;
        }
    }

    static boolean openTermux(Activity activity) {
        try {
            activity.startActivity(termuxActivityIntent());
            return true;
        } catch (RuntimeException exception) {
            return false;
        }
    }

    private static Intent termuxActivityIntent() {
        Intent foreground = new Intent(Intent.ACTION_MAIN);
        foreground.setComponent(new ComponentName(
                TermuxIdentity.PACKAGE_NAME, TermuxIdentity.ACTIVITY_NAME));
        foreground.addCategory(Intent.CATEGORY_LAUNCHER);
        foreground.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        return foreground;
    }

    private static void closeQuietly(ServerSocket server) {
        try {
            server.close();
        } catch (IOException ignored) {
        }
    }

    private static void closeQuietly(Socket socket) {
        if (socket == null) return;
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }

    private static String ACTION_SAFE() {
        return TermuxContract.ACTION_RUN_COMMAND;
    }

    private static void serve(ServerSocket server, String clientToken, String serverToken,
                              byte[] command, long deadlineNanos, Handler main, Callback callback) {
        HandoffResult result = exchangeUntilDeadline(
                server, clientToken, serverToken, command, deadlineNanos);
        main.post(() -> {
            if (result == HandoffResult.DELIVERED) callback.onHandoffComplete();
            else if (result == HandoffResult.SYNTAX_REJECTED) {
                callback.onHandoffFailed("The command has invalid Bash syntax.", false);
            } else {
                callback.onHandoffFailed(HANDOFF_TIMEOUT_MESSAGE, true);
            }
        });
    }

    static HandoffResult exchangeUntilDeadline(ServerSocket server, String clientToken,
                                                String serverToken, byte[] command,
                                                long deadlineNanos) {
        byte[] expected = clientToken.getBytes(StandardCharsets.US_ASCII);
        AtomicReference<Socket> activeSocket = new AtomicReference<>();
        ScheduledExecutorService watchdog = null;
        ScheduledFuture<?> deadlineTask = null;
        HandoffResult result = HandoffResult.EXPIRED;
        try (server) {
            long watchdogDelayNanos = deadlineNanos - System.nanoTime();
            if (watchdogDelayNanos <= 0) return result;
            watchdog = Executors.newSingleThreadScheduledExecutor(runnable -> {
                Thread thread = new Thread(runnable, "termux-vault-handoff-watchdog");
                thread.setDaemon(true);
                return thread;
            });
            deadlineTask = watchdog.schedule(() -> {
                closeQuietly(activeSocket.getAndSet(null));
                closeQuietly(server);
            }, watchdogDelayNanos, TimeUnit.NANOSECONDS);

            while (System.nanoTime() < deadlineNanos) {
                server.setSoTimeout(timeoutMillisUntil(deadlineNanos));
                Socket socket;
                try {
                    socket = server.accept();
                } catch (SocketTimeoutException exception) {
                    break;
                } catch (IOException exception) {
                    if (System.nanoTime() >= deadlineNanos || server.isClosed()) break;
                    // A reset or aborted SYN (ECONNABORTED/ECONNRESET) must not close the listener.
                    continue;
                }
                activeSocket.set(socket);
                try (socket) {
                    if (System.nanoTime() >= deadlineNanos) break;
                    socket.setTcpNoDelay(true);
                    InputStream input = socket.getInputStream();
                    OutputStream output = socket.getOutputStream();
                    long preAuthDeadlineNanos = Math.min(deadlineNanos,
                            System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(PRE_AUTH_TIMEOUT_MS));
                    byte[] received;
                    try {
                        received = readLine(
                                socket, input, MAX_HANDSHAKE_BYTES, preAuthDeadlineNanos);
                    } catch (IOException exception) {
                        if (System.nanoTime() >= deadlineNanos || server.isClosed()) break;
                        // A pre-auth peer cannot end the one-shot listener by stalling or resetting.
                        continue;
                    }
                    boolean matches = CryptoEngine.equalsConstantTime(expected, received);
                    CryptoEngine.wipe(received);
                    if (!matches) {
                        try {
                            output.write("NO\n".getBytes(StandardCharsets.US_ASCII));
                            output.flush();
                        } catch (IOException ignored) {
                            // An unauthenticated disconnect must not exhaust the listener.
                        }
                        continue;
                    }
                    byte[] reply = serverReply(command.length, serverToken);
                    try {
                        output.write(reply);
                        output.write(command);
                        output.flush();
                    } finally {
                        CryptoEngine.wipe(reply);
                    }
                    byte[] response = readLine(socket, input, 16, deadlineNanos);
                    boolean ready = CryptoEngine.equalsConstantTime(
                            "READY".getBytes(StandardCharsets.US_ASCII), response);
                    boolean invalid = CryptoEngine.equalsConstantTime(
                            "INVALID".getBytes(StandardCharsets.US_ASCII), response);
                    CryptoEngine.wipe(response);
                    if (!ready) {
                        if (invalid) result = HandoffResult.SYNTAX_REJECTED;
                        break;
                    }
                    output.write(command);
                    output.flush();
                    byte[] startedResponse = readLine(socket, input, 16, deadlineNanos);
                    boolean started = CryptoEngine.equalsConstantTime(
                            "STARTED".getBytes(StandardCharsets.US_ASCII), startedResponse);
                    CryptoEngine.wipe(startedResponse);
                    if (!started) break;
                    if (System.nanoTime() >= deadlineNanos) break;
                    output.write("GO\n".getBytes(StandardCharsets.US_ASCII));
                    output.flush();
                    try {
                        socket.shutdownOutput();
                    } catch (IOException ignored) {
                        // GO was already accepted by the local socket.
                    }
                    result = HandoffResult.DELIVERED;
                    break;
                } finally {
                    activeSocket.compareAndSet(socket, null);
                }
            }
        } catch (SocketTimeoutException exception) {
            // Reported below without including transport details in logs.
        } catch (IOException exception) {
            // Reported below without including transport details in logs.
        } catch (RuntimeException exception) {
            // A watchdog scheduling/runtime failure is reported as a closed handoff.
        } finally {
            if (deadlineTask != null) deadlineTask.cancel(false);
            if (watchdog != null) watchdog.shutdownNow();
            closeQuietly(activeSocket.getAndSet(null));
            CryptoEngine.wipe(expected);
            CryptoEngine.wipe(command);
        }
        return result;
    }

    private static byte[] readLine(Socket socket, InputStream input, int maxBytes,
                                   long deadlineNanos) throws IOException {
        byte[] buffer = new byte[maxBytes];
        int length = 0;
        try {
            while (length < maxBytes) {
                socket.setSoTimeout(timeoutMillisUntil(deadlineNanos));
                int value = input.read();
                if (value < 0 || value == '\n') break;
                if (value != '\r') buffer[length++] = (byte) value;
            }
            if (length == maxBytes) return new byte[0];
            byte[] result = new byte[length];
            System.arraycopy(buffer, 0, result, 0, length);
            return result;
        } finally {
            CryptoEngine.wipe(buffer);
        }
    }

    private static int timeoutMillisUntil(long deadlineNanos) throws SocketTimeoutException {
        long remainingNanos = deadlineNanos - System.nanoTime();
        if (remainingNanos <= 0) throw new SocketTimeoutException();
        long timeoutMillis = TimeUnit.NANOSECONDS.toMillis(remainingNanos);
        if (TimeUnit.MILLISECONDS.toNanos(timeoutMillis) < remainingNanos) timeoutMillis++;
        return (int) Math.max(1, Math.min(Integer.MAX_VALUE, timeoutMillis));
    }

    private static byte[] serverReply(int commandLength, String serverToken) {
        String length = String.format(Locale.ROOT, "%08d", commandLength);
        byte[] lengthBytes = length.getBytes(StandardCharsets.US_ASCII);
        byte[] tokenBytes = serverToken.getBytes(StandardCharsets.US_ASCII);
        byte[] reply = new byte[3 + lengthBytes.length + 1 + tokenBytes.length + 1];
        int offset = 0;
        reply[offset++] = 'O';
        reply[offset++] = 'K';
        reply[offset++] = ' ';
        System.arraycopy(lengthBytes, 0, reply, offset, lengthBytes.length);
        offset += lengthBytes.length;
        reply[offset++] = ' ';
        System.arraycopy(tokenBytes, 0, reply, offset, tokenBytes.length);
        offset += tokenBytes.length;
        reply[offset] = '\n';
        CryptoEngine.wipe(lengthBytes);
        CryptoEngine.wipe(tokenBytes);
        return reply;
    }

    private static String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) builder.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        return builder.toString();
    }

    static String sanitizeDisplayTitle(String title) {
        return TextPolicy.safeDisplayTitle(title);
    }
}
