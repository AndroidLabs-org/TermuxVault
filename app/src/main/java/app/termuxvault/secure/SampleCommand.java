package app.termuxvault.secure;

/** Non-secret defaults for the removable entry created with a new vault. */
final class SampleCommand {
    static final String TITLE = "Hello world";
    static final String COMMAND =
            "printf '%s\\n\\n' 'Hello world from Termux Vault!'\n\n"
                    + "printf '%s\\n\\n' 'Authenticated handoff to Termux succeeded.'\n\n"
                    + "printf '%s\\n\\n' 'This sample pauses after a successful run by default.'\n\n"
                    + "printf '%s\\n\\n' 'It also enables completion notifications by default.'\n\n"
                    + "printf '%s\\n' 'They appear only when Android allows notifications.'";
    static final boolean PAUSE_AFTER_SUCCESS = true;
    static final boolean NOTIFY_WHEN_FINISHED = true;
    static final boolean HIDE_TERMINAL_OUTPUT = false;

    private SampleCommand() {}
}
