package app.termuxvault.secure;

/**
 * Keeps obscured-touch policy independent from Android UI classes so every gesture-state edge
 * case can be covered by local unit tests.
 */
final class OccludedTouchGate {
    private boolean partialSelectionGestureAllowed;
    private boolean gestureBlocked;

    /**
     * Returns true when this event must not reach the window.
     *
     * <p>A directly obscured touch is never accepted. A partially obscured gesture is accepted
     * only when its DOWN began while this window had a live selection associated with an active
     * app-owned text ActionMode. The allowance lasts through that gesture because dismissing the
     * selection on DOWN removes the condition before MOVE and UP arrive.</p>
     */
    boolean shouldReject(boolean down, boolean end, boolean directlyObscured,
                         boolean partiallyObscured, boolean hasTrackedSelectionActionMode) {
        if (down) {
            partialSelectionGestureAllowed = false;
            gestureBlocked = false;
        }

        boolean reject;
        if (gestureBlocked) {
            reject = true;
        } else if (directlyObscured) {
            partialSelectionGestureAllowed = false;
            gestureBlocked = true;
            reject = true;
        } else if (partiallyObscured) {
            if (partialSelectionGestureAllowed) {
                reject = false;
            } else if (down && hasTrackedSelectionActionMode) {
                partialSelectionGestureAllowed = true;
                reject = false;
            } else {
                gestureBlocked = true;
                reject = true;
            }
        } else {
            reject = false;
        }

        if (end) {
            partialSelectionGestureAllowed = false;
            gestureBlocked = false;
        }
        return reject;
    }
}
