package app.termuxvault.secure;

import java.util.UUID;

/** Validation kept independent of Android's permissive exported-broadcast parsing. */
final class AutomationRequest {
    private AutomationRequest() {}

    static String canonicalEntryId(Object extra) {
        if (!(extra instanceof String entryId)) return null;
        try {
            String canonical = UUID.fromString(entryId).toString();
            return canonical.equals(entryId) ? canonical : null;
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }
}
