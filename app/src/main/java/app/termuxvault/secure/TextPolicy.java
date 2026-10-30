package app.termuxvault.secure;

final class TextPolicy {
    private TextPolicy() {}

    /** API-30-safe equivalent of String.isBlank(), including Unicode whitespace. */
    static boolean isBlank(String value) {
        if (value == null || value.isEmpty()) return true;
        for (int offset = 0; offset < value.length();) {
            int codePoint = value.codePointAt(offset);
            if (!Character.isWhitespace(codePoint)) return false;
            offset += Character.charCount(codePoint);
        }
        return true;
    }

    /**
     * Produces a single-line label that cannot inject terminal controls or visually reorder an
     * authorization reason. The stored title is left unchanged; this is strictly a display
     * boundary for prompts, notifications, widgets, and the Termux banner.
     */
    static String safeDisplayTitle(String title) {
        if (title == null) return "Protected command";
        StringBuilder sanitized = new StringBuilder(Math.min(title.length(), 80));
        boolean previousSpace = false;
        int codePoints = 0;
        for (int offset = 0; offset < title.length() && codePoints < 80; codePoints++) {
            int codePoint = title.codePointAt(offset);
            offset += Character.charCount(codePoint);
            if (codePoint == 0x1b && offset < title.length() && title.charAt(offset) == '[') {
                offset++;
                while (offset < title.length()) {
                    int sequencePoint = title.codePointAt(offset);
                    offset += Character.charCount(sequencePoint);
                    if (sequencePoint >= 0x40 && sequencePoint <= 0x7e) break;
                }
            }
            int type = Character.getType(codePoint);
            boolean unsafe = Character.isISOControl(codePoint)
                    || type == Character.FORMAT || type == Character.SURROGATE;
            boolean space = unsafe || Character.isWhitespace(codePoint)
                    || Character.isSpaceChar(codePoint);
            if (space) {
                if (sanitized.length() > 0 && !previousSpace) sanitized.append(' ');
                previousSpace = true;
            } else {
                sanitized.appendCodePoint(codePoint);
                previousSpace = false;
            }
        }
        int length = sanitized.length();
        if (length > 0 && sanitized.charAt(length - 1) == ' ') {
            sanitized.setLength(length - 1);
        }
        return sanitized.length() == 0 ? "Protected command" : sanitized.toString();
    }
}
