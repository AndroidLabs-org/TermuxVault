package app.termuxvault.secure;

import android.annotation.SuppressLint;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.HashMap;
import java.util.Map;

@SuppressLint("SetTextI18n")
public final class AboutActivity extends SecureActivity {
    private static final String EXTRA_SECTION =
            "app.termuxvault.secure.extra.FAQ_SECTION";
    private static final String SECTION_PREPARE_TERMUX = "prepare-termux";
    private static final String Q_PURPOSE = "What does Termux Vault do?";
    private static final String Q_PREPARE = "How do I prepare Termux?";
    private static final String Q_ADD = "How do I add and run a command?";
    private static final String Q_AT_REST = "What is encrypted at rest?";
    private static final String Q_ACCESS = "How do the passphrase and biometrics differ?";
    private static final String Q_BIOMETRIC_CLASSES =
            "Why does Termux Vault require a Class 3 biometric?";
    private static final String Q_RANDOM = "Where does Termux Vault get its randomness?";
    private static final String Q_VERIFY = "Why does Vault verify Termux?";
    private static final String Q_BACKUP = "How do encrypted backups work?";
    private static final String Q_IMPORT = "What happens when I import a backup?";
    private static final String Q_PLAINTEXT = "What is an unprotected readable backup?";
    private static final String Q_DESTRUCTIVE = "What do Delete all entries and Reset vault do?";
    private static final String Q_HANDOFF = "What happens during the handoff?";
    private static final String Q_PEER = "How does Vault know it is talking to Termux?";
    private static final String Q_DELIVERY = "How is the command delivered?";
    private static final String Q_TIMEOUT = "What if Termux startup takes longer than 12 seconds?";
    private static final String Q_LOCALHOST = "Is the localhost handoff encrypted?";
    private static final String Q_CONNECTED = "Does Vault stay connected while the command runs?";
    private static final String Q_LOCATION = "Where does the command start?";
    private static final String Q_MULTILINE = "How should I enter multi-line commands?";
    private static final String Q_HIDE = "What does Hide terminal output do?";
    private static final String Q_STATUS = "How do pause and exit status work?";
    private static final String Q_NOTIFICATIONS = "How do completion notifications work?";
    private static final String Q_LEAKS = "Can editing or the command itself leak a secret?";
    private static final String Q_AUTOMATION = "How do widgets and Tasker work?";

    private final Map<String, TextView> questionTargets = new HashMap<>();
    private ScrollView scroll;

    static Intent prepareTermuxIntent(Context context) {
        return new Intent(context, AboutActivity.class)
                .putExtra(EXTRA_SECTION, SECTION_PREPARE_TERMUX);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        scroll = new ScrollView(this);
        LinearLayout page = Ui.page(this);
        scroll.addView(page);
        TextView title = Ui.title(this, "Termux Vault FAQ");
        enableReadOnlySelection(title);
        page.addView(title, Ui.matchWrap());
        addBody(page, "This FAQ starts with the basic workflow and then explains the security "
                + "details. Tap any question below to jump to it.");
        Ui.addSpace(page, 6);
        addCopyFaqButton(page);
        addContents(page);

        addCategory(page, "Getting started");
        addSection(page, Q_PURPOSE,
                "Termux Vault keeps titled Termux commands encrypted and unlocks only the command "
                        + "you choose. After authentication, it opens a foreground Termux session "
                        + "and hands that command over for execution. Vault has no scheduler and no "
                        + "continuously running background service.");

        addHeading(page, Q_PREPARE);
        addBody(page, "Install Termux in the same Android profile as Termux Vault.");
        addSubheading(page, "1. Enable external commands in Termux");
        addBody(page, "In Termux, open:");
        addCode(page, "~/.termux/termux.properties");
        addBody(page, "The required setting is usually already present but commented out:");
        addCode(page, "# allow-external-apps = true");
        addBody(page, "Remove the leading # to enable it. If the line is missing, add it manually. "
                + "The enabled line should read:");
        addCode(page, "allow-external-apps = true");
        addBody(page, "Save the file, then run:");
        addCode(page, "termux-reload-settings");
        addBody(page, "If the change does not take effect, force stop Termux from Android App info, "
                + "then reopen it.");
        addSubheading(page, "2. Check Termux Vault’s run permission");
        addBody(page, "When you first create a vault, Android asks whether Termux Vault may run "
                + "commands in the Termux environment.");
        addBody(page, "If you did not grant this permission, open Termux Vault → Settings → Android "
                + "access → Open Termux Vault app info. Select Permissions or Additional permissions, "
                + "then allow Run commands in Termux environment.");
        addBody(page, "Vault may also ask to post notifications. Notifications are optional and "
                + "control completion notifications; they do not control whether commands can run.");
        addSubheading(page, "3. Use Display over other apps only if needed");
        addBody(page, "Display over other apps is optional. Enable it only if Termux does not open "
                + "reliably when Vault starts a command.");
        addBody(page, "In Termux Vault, open Settings → Android access → Open Termux app info, then "
                + "select Display over other apps.");
        addBody(page, "On some Android variants, including GrapheneOS, Android may initially block "
                + "this special access. If that happens, open Termux App info, tap ⋮ → Allow restricted "
                + "settings (if shown), authenticate, and try again. On some devices, "
                + "Allow restricted settings appears only after the first blocked attempt.");

        addSection(page, Q_ADD,
                "Add an entry, choose its non-sensitive title and icon, and enter the command. You can "
                        + "optionally pause after success, hide normal terminal output, or request a "
                        + "completion notification. Tap the entry or its widget and authenticate. Vault "
                        + "then verifies Termux, decrypts only that entry, completes the short handoff, "
                        + "and leaves Termux to run it.");

        addCategory(page, "Vault security");
        addSection(page, Q_AT_REST,
                "Each command payload is encrypted with its own random key. Those keys are protected "
                        + "by a random vault master key using AES-256-GCM, which also detects changes. "
                        + "The vault passphrase protects the master key through Argon2id using 64 MiB "
                        + "of memory, three iterations, and parallelism 4. Vault data stays in app-private, no-backup "
                        + "storage. Titles, icons, entry IDs, timestamps, order, run choices—including "
                        + "the output-hiding choice—pending completion-token hashes, and trusted Termux "
                        + "certificate fingerprints are metadata and are not encrypted.");

        addSection(page, Q_ACCESS,
                "The vault passphrase provides cryptographic protection, not merely an access check. "
                        + "Argon2id derives a key from it, and that key decrypts the encrypted vault "
                        + "master key. Biometric unlock is optional and adds another encrypted copy of "
                        + "the same master key, protected by a non-exportable AES key held by Android "
                        + "Keystore. Vault requests hardware backing, hardware-enforced authorization, "
                        + "enrollment invalidation, and a fresh Class 3 biometric authorization for every "
                        + "use. It checks the policy Android reports; if a functional Class 3 key does not "
                        + "confirm every requested protection, Vault lists only those fields and asks "
                        + "whether to continue. Android device credentials and Class 2 biometrics are never "
                        + "accepted for this key. The decrypted master key exists only briefly in app "
                        + "memory. The passphrase wrapper remains available "
                        + "when biometrics are enabled, so its strength still matters. If enrolled "
                        + "biometrics change, "
                        + "Android invalidates that key. Reset verifies the vault passphrase, removes "
                        + "the unusable material, and returns biometric unlock to its initial Disabled "
                        + "state. Normal biometric disabling also requires the vault passphrase. "
                        + "Changing the vault passphrase generates a new master key and re-protects "
                        + "every command, so a copy encrypted with the previous passphrase cannot "
                        + "decrypt the updated vault. Biometric unlock is then disabled until you "
                        + "enroll it again, because it wrapped the previous master key. Vault "
                        + "allows any non-empty passphrase. " + PassphraseWarning.guidance());
        addBody(page, "Passphrase fields start masked. Their eye button can temporarily reveal exactly "
                + "what you typed and automatically masks it again when the window loses focus. This "
                + "does not change how the passphrase is stored or verified.");

        addSection(page, Q_BIOMETRIC_CLASSES, BiometricEnrollmentUi.FAQ_CLASS_GUIDANCE);

        addSection(page, Q_RANDOM,
                "Termux Vault obtains all general-purpose cryptographic randomness from Android through "
                        + "java.security.SecureRandom. This includes vault master keys, individual command-"
                        + "encryption keys, salts, encryption IVs, and one-time authentication tokens. "
                        + "SecureRandom is a cryptographically strong generator "
                        + "that seeds itself from Android's platform entropy source when first used. Vault "
                        + "does not create randomness from timestamps, device identifiers, passphrases, "
                        + "network services, or user behavior.");
        addBody(page, "The biometric wrapping key is different: Android Keystore generates and holds "
                + "non-exportable key material that does not enter the application process. Vault requests "
                + "secure-hardware enforcement and explicitly reports any requested protection that Android "
                + "does not confirm.");

        addSection(page, Q_VERIFY,
                "Before decrypting and again before handoff, Vault checks the installed com.termux "
                        + "signing certificate against the certificate you trusted. The package name "
                        + "and version help you identify the app, but the signing certificate is the "
                        + "trust anchor. An unexpected certificate change blocks execution until you "
                        + "explicitly review and trust it.");

        addCategory(page, "Backups and recovery");
        addSection(page, Q_BACKUP,
                "Settings can export all entries as a versioned block of encrypted, copyable text. "
                        + "Vault first requires the vault passphrase to authorize the export. You can "
                        + "protect the result with that passphrase or enter and confirm a different, "
                        + "non-empty backup passphrase. " + PassphraseWarning.guidance()
                        + " A fresh Argon2id salt derives an independent key "
                        + "for every export, "
                        + "and AES-256-GCM encrypts the entire backup and detects an alteration.");
        addBody(page, "The backup preserves each title, icon, command, order, pause choice, notification "
                + "choice, and output-hiding choice. It does not copy the vault master key, biometric "
                + "material, trusted Termux certificates, original entry IDs or timestamps, pending "
                + "completion tokens, widget bindings, or Tasker references.");
        addBody(page, "Vault does not write the backup to a file or cache. It appears on screen and enters "
                + "Android's clipboard only after Copy. Android may reject an unusually large backup as "
                + "one clipboard item; Vault reports that instead of writing a fallback file.");

        addSection(page, Q_IMPORT,
                "Paste an encrypted or unprotected backup into Import backup. Vault validates the entire "
                        + "backup before showing how many entries it contains. Review detects encrypted "
                        + "backup text and then opens a protected backup-passphrase dialog; unprotected JSON "
                        + "does not show that dialog. A wrong passphrase clears only the passphrase field, "
                        + "leaving the pasted encrypted backup available for another attempt. After you "
                        + "confirm and unlock "
                        + "the current vault, every entry is appended to the end with fresh encryption. "
                        + "Existing entries are never changed or removed. Vault does not rename, skip, or "
                        + "combine duplicates; identical titles and commands are allowed.");
        addBody(page, "Each imported entry receives a new internal UUID and new timestamps, but its title "
                + "and command stay unchanged. The new UUID prevents an imported entry from colliding with "
                + "an existing entry record; it is not part of the visible title. If the backup is "
                + "invalid, its passphrase is wrong, the vault would exceed 200 entries, authentication is "
                + "cancelled, or saving fails, no entries are imported.");

        addSection(page, Q_PLAINTEXT,
                "The Danger zone can export the same entry data as readable, indented JSON. It is plain "
                        + "text—not Base64 and not encryption—so a person can directly read every title and "
                        + "command. The JSON identifies its format and version but deliberately has no "
                        + "cryptographic integrity or authenticity protection. It can be edited before "
                        + "import, and Vault will accept it only if the complete structure and every entry "
                        + "are valid.");
        addBody(page, "This export requires the vault passphrase and a strong warning, but that does not "
                + "protect the resulting text. Copying it places all command secrets on Android's clipboard, "
                + "outside Vault's protection. Store it only where plaintext is safe and clear the clipboard "
                + "afterward. Prefer an encrypted backup for normal use.");

        addSection(page, Q_DESTRUCTIVE,
                "Both destructive actions require the vault passphrase and a typed confirmation; biometric "
                        + "unlock alone is not accepted. Delete all entries empties the current command list "
                        + "but keeps the vault passphrase, biometric setting, and trusted Termux identity. "
                        + "Reset vault removes the complete vault and returns the app to initial setup. "
                        + "Existing widgets return to Choose command. Neither action can be undone, and flash "
                        + "storage cannot promise forensic erasure of previously written blocks.");

        addCategory(page, "Secure handoff");
        addSection(page, Q_HANDOFF,
                "The short version is: Vault verifies Termux, asks its fixed service to create a "
                        + "terminal session, and immediately asks Android to bring Termux to the "
                        + "foreground. Termux sends a fresh client token to prove it received Vault's "
                        + "private launch information; Vault returns a different fresh token so Termux "
                        + "can verify the reply came from the same one-time handoff. Termux then validates "
                        + "the command, prepares its memory-only execution path, receives Vault's final "
                        + "GO reply, and runs it. Vault closes the connection and wipes its decrypted copy.");

        addSection(page, Q_PEER,
                "Vault first verifies Termux's Android signing certificate. It then sends a fixed "
                        + "bootstrap, a random localhost port, two fresh 256-bit one-use authentication "
                        + "tokens, the non-sensitive title, and run settings directly to Termux through "
                        + "Android Binder IPC using an explicit service Intent. If a completion "
                        + "notification is selected, that request also includes its own fresh one-use "
                        + "callback token. Explicit means the request names Termux's exact service; it is "
                        + "not a broadcast, does not use the internet, and ordinary apps do not receive "
                        + "it. The saved command, passwords or credentials inside that command, and vault "
                        + "keys are never included in the Intent. The temporary tokens are the only secret "
                        + "launch values.");
        addBody(page, "Termux connects to the supplied localhost port and sends the client token. "
                + "Vault checks it, then replies with the server token followed by a validation copy "
                + "of the command. Termux checks that token before accepting or parsing the copy. It "
                + "reports successful validation before Vault sends the execution copy. Each side has "
                + "therefore proved that it received the original private launch information, and no "
                + "command can execute before the final GO reply. The tokens expire with the 12-second "
                + "handoff and are never reused.");

        addSection(page, Q_DELIVERY,
                "After mutual authentication, Vault streams the same command bytes once for silent Bash "
                        + "syntax validation and once for execution. The validation copy is parsed but "
                        + "not run. Termux holds the execution copy only in memory, creates an anonymous "
                        + "kernel pipe, reports that the pipe is ready, and waits for Vault's final GO "
                        + "reply. The protected Bash child starts only after GO and reads the command from "
                        + "that pipe. No command file or named pipe is created, and terminal input stays "
                        + "attached normally. Supported Termux versions are also asked not to create "
                        + "per-command result or terminal-output logs.");

        addSection(page, Q_TIMEOUT,
                "The 12-second timer starts before Vault asks Termux to run, so custom namespace setup or "
                        + "a superuser approval is part of that window. If the authenticated exchange and "
                        + "memory-only preparation do not finish in time, Vault closes the listener and "
                        + "wipes the decrypted command. Without GO, Termux does not start the protected "
                        + "child. If Termux did not open in the foreground, Android may have blocked it; "
                        + "check that Display over other apps is enabled for Termux. If Termux opened, "
                        + "startup or superuser approval may have taken too long. After checking the "
                        + "applicable cause, return to Vault and try again. While the run screen remains "
                        + "in memory, Vault retains only this fixed, non-sensitive failure and shows its "
                        + "timeout dialog when you return; the dialog can open Termux App info directly. "
                        + "If Android kills the entire Vault process, Termux still shows its retry message, "
                        + "but no app screen remains to recover the Vault dialog.");

        addSection(page, Q_LOCALHOST,
                "The localhost stream is mutually authenticated, but it is not wrapped in a second TLS "
                        + "or AES tunnel. It is bound to 127.0.0.1 and never crosses Wi-Fi, mobile data, or "
                        + "another network interface. Android app isolation prevents an ordinary app from "
                        + "passively reading another app's socket traffic, while the fresh tokens reject "
                        + "unauthorized connections. Because Termux must execute plaintext, the command "
                        + "briefly exists in Vault memory, Android kernel buffers, the Termux anonymous "
                        + "pipe, and the executing shell's memory. A rooted or compromised OS, debugger, "
                        + "privileged packet capture, or malicious trusted Termux build is outside this "
                        + "threat model. Transport encryption would add complexity without protecting "
                        + "either compromised endpoint.");

        addSection(page, Q_CONNECTED,
                "No. Once Termux has authenticated, prepared the execution copy, and received GO, Vault "
                        + "closes the socket and wipes its command arrays. Termux then runs independently; "
                        + "closing or swiping away Vault does not stop it. An optional completion "
                        + "notification returns later through a separate authenticated Android broadcast, "
                        + "not the handoff socket. Android can recreate Vault's receiver if its UI was "
                        + "closed, although force-stopping Vault blocks that receiver until Vault is opened "
                        + "again.");

        addCategory(page, "Running commands");
        addHeading(page, Q_LOCATION);
        addBody(page, "Vault leaves Termux's working-directory setting unset, so Termux chooses the "
                + "current Android profile's $HOME. To start elsewhere, make the change of directory part "
                + "of the saved command:");
        addCode(page, "cd -- \"/full/path\" || exit 1\nrest_of_command");

        addHeading(page, Q_MULTILINE);
        addBody(page, "For a multi-step command, enter each step on its own command line. Termux "
                + "Vault sends the command lines to Termux in order, so wrapping the entire entry "
                + "in another bash -lc command is normally unnecessary.");
        addBody(page, "Short shell wrappers are supported, but combining a large script, extensive "
                + "quoting, background jobs, and many operations into one heavily nested line can "
                + "make failures difficult to identify. Using separate command lines makes the "
                + "entry easier to read, run, and troubleshoot.");
        addBody(page, "If Termux opens but no output appears, temporarily replace the entry with a "
                + "simple test:");
        addCode(page, "echo \"Termux Vault command received\"");
        addBody(page, "If that works, add the original command lines back gradually to identify the "
                + "line causing the problem.");
        addBody(page, "For especially large scripts, you can store the script in Termux and have "
                + "Vault run it. Remember that an external script is stored outside Termux Vault "
                + "and is not encrypted or protected by the vault, so do not place passphrases, "
                + "credentials, or other secrets in it.");

        addSection(page, Q_HIDE,
                "Hide terminal output is optional and off by default. When enabled, the protected "
                        + "command's normal stdout and stderr are redirected to /dev/null instead of being "
                        + "shown or collected. Termux still shows the non-sensitive title, one generic "
                        + "final success-or-failure result, and any selected pause prompt. Per-line command "
                        + "diagnostics are hidden too. Vault's fixed syntax or handoff errors can still "
                        + "appear because they do not contain the command.");
        addBody(page, "This reduces accidental leaks but is not a sandbox. A command can deliberately "
                + "write to /dev/tty, files, logs, notifications, the clipboard, or the network, and its "
                + "own redirections still work. Interactive prompts may also be hidden, so an interactive "
                + "command can appear stuck. Typed input may echo unless that command disables terminal "
                + "echo itself.");

        addSection(page, Q_STATUS,
                "The pause option does not modify the saved command. A fixed parent waits for the protected "
                        + "child and keeps track of ordinary unhandled Bash failures. An earlier failure "
                        + "remains a failure even if a later line succeeds. Vault does not enable set -e or "
                        + "pipefail, so normal Bash rules for conditionals, pipelines, subshells, exit, and "
                        + "exec still apply. Every run ends with either “"
                        + RunOutcomeText.SUCCESS_SENTENCE + "” or “"
                        + RunOutcomeText.FAILURE_SENTENCE
                        + "” Failures wait for Enter automatically; the "
                        + "checkbox adds that wait after success. With output visible, missing commands show "
                        + "only “Command not found on line N,” while other detected failures show the saved-"
                        + "command line and numeric exit status. Hidden-output mode suppresses those per-line "
                        + "messages and keeps only the aggregate result. The removable Hello world entry "
                        + "created with a new vault keeps terminal output visible, demonstrates the "
                        + "authenticated in-memory handoff, and pauses after success.");

        addSection(page, Q_NOTIFICATIONS,
                "Enable Notify when finished on an entry. When the protected shell returns, Termux sends "
                        + "Vault only a random run ID, a fresh 256-bit callback token, and the aggregate "
                        + "outcome. Vault stores only the token's hash, the non-sensitive title, and creation "
                        + "time. It consumes a valid token once and separately confirms that Termux is still "
                        + "trusted. The command, terminal transcript, stdout, and stderr are never returned. "
                        + "The callback has a short hard timeout and cannot change the command's result. Tap "
                        + "the notification to open Termux. Android notification permission and the Command "
                        + "completions channel must be enabled; Settings shows both notification channels "
                        + "and recovery links when either channel alone is disabled. The removable Hello "
                        + "world entry created with a new vault enables completion notification by default "
                        + "to demonstrate this path; if notifications are blocked, the command still runs "
                        + "without one.");

        addCategory(page, "Privacy and integrations");
        addSection(page, Q_LEAKS,
                "The command editor supports normal copy, cut, and paste. Copying or cutting deliberately "
                        + "places plaintext in Android's clipboard, outside the vault, so clear it when "
                        + "finished. Vault never copies commands automatically; a backup reaches the "
                        + "clipboard only when you explicitly tap its Copy button. Passphrase eye buttons reveal "
                + "text only after you tap them; fields start masked and remask when the app window "
                + "loses focus. Screenshots are blocked. On Android 12 and newer, untrusted overlays "
                + "are hidden; obscured touches are rejected on every supported Android version. "
                + "Sensitive fields also disable autofill, Android Assist/content capture, text "
                + "classification, Share, and Process Text.");
        addBody(page, "The keyboard's no-learning request is advisory: the active keyboard can see what you "
                + "type and must be trusted. Enabled accessibility services can also observe or change visible "
                + "content. A command may reveal its own secrets through output, tracing it enables, process "
                + "arguments, files, application logs, network requests, or the clipboard. Hide terminal "
                + "output reduces normal stdout/stderr exposure but cannot prevent deliberate output. Prefer "
                + "standard input over process arguments when supported. Vault never requests root, although "
                + "a saved command may invoke a root helper inside Termux.");

        addSection(page, Q_AUTOMATION,
                "To add a widget, long-press an empty area of the Android home screen, choose Widgets, find "
                        + "Termux Vault, and drag its 1×1 widget into place. Select a fixed command, or choose "
                        + "Choose each time to keep one widget labeled Choose command. That mode shows the "
                        + "current command list on every tap. Either mode still requires authentication.");
        addBody(page, "For Tasker, long-press an entry in Vault and choose Tasker ID. In Tasker, add "
                + "a Send Intent action. The Vault dialog provides separate Copy buttons for Action, "
                + "Package, and Extra, plus Copy all. Use Action “"
                + AutomationContract.action(getPackageName()) + "”, Package “" + getPackageName()
                + "”, Extra “entry_id:<the displayed UUID>”, and Target “Broadcast Receiver”. Tasker "
                + "creates a notification in the Tasker authentication requests channel; "
                + "tap it and authenticate to run. Android notification permission is required. Neither "
                + "widgets nor Tasker can decrypt or run a command unattended.");

        Ui.addSpace(page, 12);
        addCopyFaqButton(page);
        Ui.addSpace(page, 8);
        Button close = Ui.button(this, "Close");
        close.setOnClickListener(view -> finish());
        page.addView(close, Ui.matchWrap());
        setContentView(scroll);
        if (SECTION_PREPARE_TERMUX.equals(getIntent().getStringExtra(EXTRA_SECTION))) {
            scrollToQuestion(Q_PREPARE, false);
        }
    }

    private void addCopyFaqButton(LinearLayout page) {
        Button copy = Ui.button(this, "Copy entire FAQ");
        copy.setOnClickListener(view -> copyEntireFaq(page));
        page.addView(copy, Ui.matchWrap());
    }

    private void copyEntireFaq(View root) {
        StringBuilder text = new StringBuilder();
        appendVisibleText(root, text);
        try {
            ClipboardManager clipboard = getSystemService(ClipboardManager.class);
            if (clipboard == null) throw new IllegalStateException("Clipboard unavailable");
            clipboard.setPrimaryClip(ClipData.newPlainText(
                    "Termux Vault FAQ", text.toString().trim()));
            Toast.makeText(this, "FAQ copied", Toast.LENGTH_SHORT).show();
        } catch (RuntimeException exception) {
            Toast.makeText(this, "Android could not copy the FAQ", Toast.LENGTH_SHORT).show();
        }
    }

    private static void appendVisibleText(View view, StringBuilder output) {
        if (view.getVisibility() != View.VISIBLE || view instanceof Button) return;
        if (view instanceof TextView textView) {
            CharSequence value = textView.getText();
            if (value != null && value.length() > 0) {
                if (output.length() > 0) output.append("\n\n");
                output.append(value);
            }
            return;
        }
        if (view instanceof ViewGroup group) {
            for (int index = 0; index < group.getChildCount(); index++) {
                appendVisibleText(group.getChildAt(index), output);
            }
        }
    }

    private void addContents(LinearLayout page) {
        addCategory(page, "Contents");
        addTocCategory(page, "Getting started", Q_PURPOSE, Q_PREPARE, Q_ADD);
        addTocCategory(page, "Vault security", Q_AT_REST, Q_ACCESS, Q_BIOMETRIC_CLASSES,
                Q_RANDOM, Q_VERIFY);
        addTocCategory(page, "Backups and recovery", Q_BACKUP, Q_IMPORT,
                Q_PLAINTEXT, Q_DESTRUCTIVE);
        addTocCategory(page, "Secure handoff", Q_HANDOFF, Q_PEER, Q_DELIVERY,
                Q_TIMEOUT, Q_LOCALHOST, Q_CONNECTED);
        addTocCategory(page, "Running commands", Q_LOCATION, Q_MULTILINE, Q_HIDE, Q_STATUS,
                Q_NOTIFICATIONS);
        addTocCategory(page, "Privacy and integrations", Q_LEAKS, Q_AUTOMATION);
    }

    private void addTocCategory(LinearLayout page, String category, String... questions) {
        TextView label = Ui.heading(this, category, 15, Ui.TEXT);
        enableReadOnlySelection(label);
        page.addView(label, Ui.matchWrap());
        for (String question : questions) {
            TextView link = Ui.text(this, question, 15, Ui.ACCENT);
            link.setPaintFlags(link.getPaintFlags() | Paint.UNDERLINE_TEXT_FLAG);
            link.setGravity(Gravity.CENTER_VERTICAL);
            link.setMinHeight(Ui.dp(this, 48));
            link.setClickable(true);
            link.setFocusable(true);
            link.setContentDescription("Go to “" + question + "”");
            link.setOnClickListener(view -> scrollToQuestion(question, true));
            page.addView(link, Ui.matchWrap());
        }
        Ui.addSpace(page, 8);
    }

    private void scrollToQuestion(String question, boolean smooth) {
        scroll.post(() -> {
            TextView target = questionTargets.get(question);
            if (target == null) return;
            int y = Math.max(0, target.getTop() - Ui.dp(this, 8));
            if (smooth) scroll.smoothScrollTo(0, y);
            else scroll.scrollTo(0, y);
            target.requestFocus();
            target.sendAccessibilityEvent(AccessibilityEvent.TYPE_VIEW_FOCUSED);
        });
    }

    private void addCategory(LinearLayout page, String value) {
        Ui.addSpace(page, 18);
        TextView category = Ui.heading(this, value, 20, Ui.ACCENT);
        enableReadOnlySelection(category);
        page.addView(category, Ui.matchWrap());
        Ui.addSpace(page, 4);
    }

    private void addSection(LinearLayout page, String heading, String body) {
        addHeading(page, heading);
        addBody(page, body);
    }

    private void addHeading(LinearLayout page, String value) {
        Ui.addSpace(page, 14);
        TextView heading = Ui.heading(this, value, 18, Ui.TEXT);
        heading.setFocusable(true);
        enableReadOnlySelection(heading);
        page.addView(heading, Ui.matchWrap());
        questionTargets.put(value, heading);
        Ui.addSpace(page, 5);
    }

    private void addSubheading(LinearLayout page, String value) {
        Ui.addSpace(page, 8);
        TextView subheading = Ui.heading(this, value, 15, Ui.TEXT);
        enableReadOnlySelection(subheading);
        page.addView(subheading, Ui.matchWrap());
        Ui.addSpace(page, 4);
    }

    private void addBody(LinearLayout page, String value) {
        TextView body = Ui.text(this, value, 14, Ui.MUTED);
        body.setLineSpacing(0, 1.08f);
        enableReadOnlySelection(body);
        page.addView(body, Ui.matchWrap());
        Ui.addSpace(page, 5);
    }

    private void addCode(LinearLayout page, String value) {
        Ui.addSpace(page, 4);
        TextView code = Ui.text(this, value, 14, Ui.TEXT);
        code.setTypeface(Typeface.MONOSPACE);
        enableReadOnlySelection(code);
        code.setBackgroundColor(Ui.SURFACE);
        code.setPadding(Ui.dp(this, 12), Ui.dp(this, 10), Ui.dp(this, 12), Ui.dp(this, 10));
        page.addView(code, Ui.matchWrap());
        Ui.addSpace(page, 6);
    }
}
