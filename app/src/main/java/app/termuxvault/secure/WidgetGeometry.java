package app.termuxvault.secure;

final class WidgetGeometry {
    static final float DEFAULT_PORTRAIT_WIDTH_DP = 57f;
    static final float DEFAULT_PORTRAIT_HEIGHT_DP = 102f;
    static final float DEFAULT_LANDSCAPE_WIDTH_DP = 127f;
    static final float DEFAULT_LANDSCAPE_HEIGHT_DP = 51f;

    private static final float EDGE_INSET_DP = 4f;
    private static final float MAX_TILE_SIDE_DP = 128f;
    private static final float FALLBACK_TILE_SIDE_DP = 48f;

    private WidgetGeometry() {}

    static boolean isUsableHostSize(float widthDp, float heightDp) {
        return Float.isFinite(widthDp) && Float.isFinite(heightDp)
                && widthDp > 0f && heightDp > 0f;
    }

    static float tileSideDp(float widthDp, float heightDp) {
        if (!isUsableHostSize(widthDp, heightDp)) return FALLBACK_TILE_SIDE_DP;
        float limitingSide = Math.min(widthDp, heightDp);
        float inset = Math.min(EDGE_INSET_DP, Math.max(0f, limitingSide - 1f));
        return Math.min(MAX_TILE_SIDE_DP, Math.max(1f, limitingSide - inset));
    }

    static float titleTextSp(float tileSideDp) {
        if (tileSideDp < 46f) return 10f;
        if (tileSideDp < 68f) return 12f;
        if (tileSideDp < 92f) return 14f;
        return 16f;
    }

    static float glyphTextSp(float tileSideDp) {
        if (tileSideDp < 60f) return 8f;
        if (tileSideDp < 92f) return 10f;
        return 12f;
    }

    static int titleMaxLines(float tileSideDp) {
        return tileSideDp < 68f ? 2 : 3;
    }
}
