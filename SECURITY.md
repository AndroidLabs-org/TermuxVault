# Security model

## Protected

- Command payload confidentiality and integrity at rest.
- A vault passphrase cryptographically wraps the vault master key and is hardened with Argon2id
  (64 MiB, three iterations, parallelism 4); it is not merely an application access check. Changing the passphrase
  generates a new master key, re-wraps every command key, and removes the biometric wrapper so an
  older vault file plus the previous passphrase cannot decrypt later commands.
- Optional per-use, Class 3 biometric-only Android Keystore authorization with requested enrollment
  invalidation. Device credentials and Class 2 biometrics are never accepted for the key operation.
- Itemized verification of the optional key's reported Keystore policy. A functional Class 3 key
  with unconfirmed requested protections is used only after an explicit compatibility warning;
  missing, invalidated, or cryptographically unusable keys fall back to the vault passphrase.
- Termux package certificate continuity and an authenticated replacement flow.
- Two independent fresh random 256-bit tokens mutually authenticate each short-lived localhost
  command handoff.
- An independent one-time 256-bit bearer token and current signing-certificate trust authenticate
  each optional completion event without returning terminal output.
- No command payload in Android Binder extras, process arguments, shell history, app-owned working
  or cache files, crash analytics, or app logs.
- Encrypted portable backups use an independently derived Argon2id key, fresh salt and IV, and
  AES-256-GCM authenticated encryption. Import validates the complete versioned payload before an
  atomic merge.
- General random keys, salts, IVs, and one-use tokens come from Android's
  `java.security.SecureRandom`. The app does not manually seed it with low-entropy application data.
- The Binder launch is an explicit service Intent addressed to the verified Termux component. It
  carries only the fixed bootstrap, ephemeral port and one-run tokens, non-secret title, and run
  settings; it never carries the saved command, its credentials, or vault keys.
- Screenshot protection on all supported versions and untrusted-overlay hiding on Android 12 and
  newer. Directly obscured touches are always rejected. Partial touches are rejected by default;
  Android 12 and newer allow only one gesture that begins with a live, tracked text selection so an
  outside tap can close the platform selection toolbar. Android 11 retains unconditional partial-
  touch rejection. Sensitive UI also applies autofill, Android Assist/content-capture, and text-
  classification protections. The command editor removes standard Share and Process Text actions.

## Explicit boundaries

- A compromised OS, root process, live process debugger, malicious trusted Termux build, or hostile
  destination program is outside the model.
- Any non-empty vault or backup passphrase is accepted. Values that are shorter than 12 characters
  or missing uppercase, lowercase, a number, or a symbol receive a warning, not a block. Argon2id slows offline guessing but does
  not make a weak passphrase safe; biometric unlock adds a Keystore-protected encrypted wrapper and
  does not remove the passphrase wrapper. Termux Vault requests hardware backing, hardware-enforced
  authorization, per-use Class 3 authentication, and enrollment invalidation. Some older or modified
  Android implementations may report a policy difference even though the Class 3 key and cipher are
  functional. The app lists those differences and lets the user keep passphrase-only access or
  explicitly accept the compatibility warning; it does not describe an unconfirmed field as proven.
- Entry titles, icons, UUIDs, timestamps, ordering, pause/output/notification choices, pending
  completion token hashes, and Termux certificate fingerprints are metadata and are not encrypted.
  Command payloads are encrypted.
- An encrypted portable backup contains commands only as authenticated ciphertext. It intentionally
  omits vault keys and wrapping data, biometric material, trusted Termux certificates, original
  entry UUIDs and timestamps, completion tokens, widget bindings, and Tasker references. Its security
  depends on the selected backup passphrase; any non-empty value is accepted and values that miss the
  recommended length or character policy receive a warning. The same warning applies when the vault
  passphrase is selected to protect the backup. A separately selected backup passphrase must be
  entered twice and is not saved by the app.
- The advanced unprotected export is indented, human-readable JSON and deliberately provides no
  encryption, checksum, signature, or authenticity. Its format marker and strict schema validation
  detect malformed input, not a deliberate valid edit. Creating it requires the vault passphrase and
  an explicit warning, but its commands and credentials are plaintext on screen and on the clipboard
  after the user presses Copy.
- Import is append-only and preserves duplicate titles and commands. Every imported entry receives a
  new internal UUID, timestamps, per-entry key, and ciphertext; the visible title and command do not
  change. Existing entries are not overwritten or removed, and any validation, authentication,
  capacity, or save failure imports nothing.
- The authenticated command editor deliberately supports copy, cut, and paste. Copying or cutting
  exports plaintext to Android's clipboard and is outside vault protection. Paste imports clipboard
  plaintext into the editor.
- The no-personalized-learning IME flag is advisory. The active keyboard has an input connection to
  sensitive fields and must be trusted. Assist/content-capture redaction does not constrain an
  enabled accessibility service; such a service can observe or change visible editor content and
  must also be trusted.
- Exact command behavior is user-controlled. Output and child-process arguments may expose values if
  the command is written that way.
- Optional output hiding redirects only the protected child's inherited stdout and stderr to
  `/dev/null`; it does not store that output. It cannot stop deliberate output to `/dev/tty`, files,
  logs, notifications, the clipboard, or the network, and it can hide interactive prompts.
- The localhost handoff is mutually authenticated but is not separately encrypted. Plaintext briefly exists
  in Vault memory, Android kernel socket buffers, the anonymous execution-pipe buffer, and the executing shell's
  memory. It is bound to `127.0.0.1` and is not routed over an external network interface.
- The exported completion receiver accepts only its explicit action, a currently trusted installed
  Termux signing certificate, a live random run ID, and a matching one-time 256-bit bearer token that
  is consumed once. TermuxAm does not share broadcast sender identity with manifest receivers, so the
  live token—not Android sender metadata—authorizes the callback. It receives only aggregate outcome
  metadata, never the command or terminal transcript.
- Completion notification delivery is best effort. The callback is hard-bounded and cannot delay the
  terminal indefinitely or alter its status. A killed wrapper, blocked notification channel, or
  deliberately force-stopped app can prevent delivery; detached work may continue after the protected
  child shell reports completion.
- Delete all entries and Reset vault require the vault passphrase and a typed confirmation; biometric
  authorization alone is not accepted. Flash storage does not provide reliable secure deletion.
  Removing entries or the vault removes them from active app state but does not claim forensic erasure
  of old storage blocks.

## Reports

Please report a suspected vulnerability privately to info@androidlabs.org, not in a public issue.
Include the app version, your Android version, and the steps to reproduce; never include your
vault passphrase, your commands or a backup string.

Treat any unintentional path that can place command plaintext into an Intent, argument vector,
regular file, clipboard, Android log, history file, notification, or widget as a security defect. The
clipboard exceptions are an explicit user copy or cut from the authenticated command editor and an
explicit Copy action for a user-authorized portable backup. The unprotected JSON export is itself an
explicit, strongly warned plaintext disclosure.
