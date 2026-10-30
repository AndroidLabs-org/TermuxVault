package app.termuxvault.secure;

import java.util.LinkedHashMap;
import java.util.Map;

/** A thread-safe, fixed-window throttle backed by a replaceable persistent marker set. */
final class PerEntryThrottle {
    interface Store {
        Map<String, ?> read();

        void replace(Map<String, Long> markers);
    }

    private final Object lock = new Object();
    private final String keyPrefix;
    private final long minimumIntervalMs;

    PerEntryThrottle(String keyPrefix, long minimumIntervalMs) {
        if (keyPrefix == null || keyPrefix.isEmpty() || minimumIntervalMs <= 0) {
            throw new IllegalArgumentException("Invalid throttle configuration");
        }
        this.keyPrefix = keyPrefix;
        this.minimumIntervalMs = minimumIntervalMs;
    }

    boolean tryAcquire(Store store, String entryId, long now) {
        if (store == null || entryId == null || entryId.isEmpty() || now < 0) return false;
        synchronized (lock) {
            Map<String, ?> stored = store.read();
            Map<String, Long> active = new LinkedHashMap<>();
            boolean pruned = false;
            if (stored != null) {
                for (Map.Entry<String, ?> marker : stored.entrySet()) {
                    String key = marker.getKey();
                    Object value = marker.getValue();
                    if (key == null || !key.startsWith(keyPrefix) || !(value instanceof Long)) {
                        pruned = true;
                        continue;
                    }
                    long timestamp = (Long) value;
                    // A future marker means elapsedRealtime restarted, normally after a reboot.
                    if (timestamp < 0 || timestamp > now
                            || now - timestamp >= minimumIntervalMs) {
                        pruned = true;
                        continue;
                    }
                    active.put(key, timestamp);
                }
            }

            String key = keyPrefix + entryId;
            if (active.containsKey(key)) {
                if (pruned) store.replace(active);
                return false;
            }
            active.put(key, now);
            store.replace(active);
            return true;
        }
    }

    void clear(Store store) {
        if (store == null) throw new IllegalArgumentException("Missing throttle store");
        synchronized (lock) {
            store.replace(new LinkedHashMap<>());
        }
    }
}
