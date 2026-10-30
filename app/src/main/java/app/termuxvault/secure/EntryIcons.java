package app.termuxvault.secure;

import java.util.LinkedHashMap;
import java.util.Map;

final class EntryIcons {
    static final String DEFAULT = "terminal";
    private static final LinkedHashMap<String, String> ICONS = new LinkedHashMap<>();

    static {
        ICONS.put("terminal", ">_");
        ICONS.put("key", "◆");
        ICONS.put("server", "▣");
        ICONS.put("cloud", "☁");
        ICONS.put("sync", "↻");
        ICONS.put("lightning", "ϟ");
    }

    private EntryIcons() {}

    static boolean isKnown(String id) {
        return ICONS.containsKey(id);
    }

    static String glyph(String id) {
        return ICONS.getOrDefault(id, ICONS.get(DEFAULT));
    }

    static String[] ids() {
        return ICONS.keySet().toArray(new String[0]);
    }

    static String[] labels() {
        return new String[]{"Terminal  >_", "Key  ◆", "Server  ▣", "Cloud  ☁", "Sync  ↻", "Lightning  ϟ"};
    }
}
