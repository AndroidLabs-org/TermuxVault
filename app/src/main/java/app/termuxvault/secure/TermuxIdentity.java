package app.termuxvault.secure;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

final class TermuxIdentity {
    static final String PACKAGE_NAME = "com.termux";
    static final String ACTIVITY_NAME = "com.termux.app.TermuxActivity";
    static final String RUN_SERVICE_NAME = "com.termux.app.RunCommandService";
    private static final int MAX_DISPLAY_VERSION_LENGTH = 80;

    final List<String> certificateDigests;
    final long versionCode;
    final String versionName;
    final boolean multipleSigners;

    TermuxIdentity(List<String> certificateDigests, long versionCode, String versionName,
                   boolean multipleSigners) {
        this.certificateDigests = certificateDigests;
        this.versionCode = versionCode;
        this.versionName = versionName;
        this.multipleSigners = multipleSigners;
    }

    static TermuxIdentity read(Context context) throws PackageManager.NameNotFoundException, VaultException {
        PackageManager manager = context.getPackageManager();
        PackageInfo info;
        if (Build.VERSION.SDK_INT >= 33) {
            info = manager.getPackageInfo(PACKAGE_NAME,
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES));
        } else {
            //noinspection deprecation
            info = manager.getPackageInfo(PACKAGE_NAME, PackageManager.GET_SIGNING_CERTIFICATES);
        }
        SigningInfo signingInfo = info.signingInfo;
        if (signingInfo == null) throw new VaultException("Termux signing information is unavailable");
        boolean multipleSigners = signingInfo.hasMultipleSigners();
        Signature[] signatures = multipleSigners
                ? signingInfo.getApkContentsSigners()
                : signingInfo.getSigningCertificateHistory();
        if (signatures == null || signatures.length == 0) {
            throw new VaultException("Termux signing information is unavailable");
        }
        try {
            Set<String> unique = new LinkedHashSet<>();
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            for (Signature signature : signatures) {
                byte[] digest = sha256.digest(signature.toByteArray());
                unique.add(hex(digest));
                CryptoEngine.wipe(digest);
                sha256.reset();
            }
            List<String> certificates = new ArrayList<>(unique);
            Collections.sort(certificates);
            return new TermuxIdentity(certificates, info.getLongVersionCode(), info.versionName,
                    multipleSigners);
        } catch (Exception exception) {
            throw new VaultException("Termux identity could not be verified", exception);
        }
    }

    boolean matches(List<String> trusted) {
        if (trusted == null || trusted.isEmpty()) return false;
        if (multipleSigners) {
            return trusted.size() == certificateDigests.size()
                    && trusted.containsAll(certificateDigests);
        }
        for (String certificate : certificateDigests) {
            if (trusted.contains(certificate)) return true;
        }
        return false;
    }

    String displayFingerprints() {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < certificateDigests.size(); i++) {
            if (i > 0) builder.append("\n");
            String digest = certificateDigests.get(i);
            for (int j = 0; j < digest.length(); j += 2) {
                if (j > 0) builder.append(':');
                builder.append(digest, j, j + 2);
            }
        }
        return builder.toString();
    }

    String displayVersion() {
        String safeVersionName = sanitizeVersionName(versionName);
        if (safeVersionName.isEmpty()) return Long.toString(versionCode);
        return safeVersionName + " (" + versionCode + ")";
    }

    static String sanitizeVersionName(String value) {
        if (value == null || value.isEmpty()) return "";
        StringBuilder safe = new StringBuilder(Math.min(value.length(), MAX_DISPLAY_VERSION_LENGTH));
        boolean pendingSpace = false;
        for (int offset = 0; offset < value.length();) {
            int codePoint = Character.codePointAt(value, offset);
            offset += Character.charCount(codePoint);
            if (codePoint < 0x21 || codePoint > 0x7e) {
                pendingSpace = safe.length() != 0;
                continue;
            }
            if (pendingSpace) {
                if (safe.length() >= MAX_DISPLAY_VERSION_LENGTH - 1) break;
                safe.append(' ');
                pendingSpace = false;
            }
            if (safe.length() >= MAX_DISPLAY_VERSION_LENGTH) break;
            safe.append((char) codePoint);
        }
        return safe.toString();
    }

    String displayDetails() {
        return "Package: " + PACKAGE_NAME
                + "\nVersion: " + displayVersion()
                + "\n\nSHA-256 signing certificate:\n" + displayFingerprints();
    }

    private static String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) builder.append(String.format(Locale.ROOT, "%02X", value & 0xff));
        return builder.toString();
    }
}
