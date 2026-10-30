package app.termuxvault.secure;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.pm.ActivityInfo;
import android.graphics.Insets;
import android.graphics.Path;
import android.graphics.Region;
import android.os.Build;
import android.os.Bundle;
import android.text.Layout;
import android.text.Selection;
import android.text.Spannable;
import android.view.ActionMode;
import android.view.KeyEvent;
import android.view.KeyboardShortcutGroup;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.SearchEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityEvent;
import android.widget.EditText;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

abstract class SecureActivity extends Activity {
    private final SelectionDismissalController selectionDismissal =
            new SelectionDismissalController();
    private final OccludedTouchGate activityTouchGate = new OccludedTouchGate();
    private View insetContent;
    private final Set<EditText> sensitiveText =
            Collections.newSetFromMap(new IdentityHashMap<>());
    private final Set<Runnable> foregroundLossObservers =
            Collections.newSetFromMap(new IdentityHashMap<>());
    private boolean secureSessionActive = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(null);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        if (Build.VERSION.SDK_INT >= 31) getWindow().setHideOverlayWindows(true);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LOCKED);
    }

    @Override
    public void setContentView(View view) {
        super.setContentView(view);
        View content = findViewById(android.R.id.content);
        if (content != insetContent) {
            insetContent = content;
            int initialLeft = content.getPaddingLeft();
            int initialTop = content.getPaddingTop();
            int initialRight = content.getPaddingRight();
            int initialBottom = content.getPaddingBottom();
            content.setOnApplyWindowInsetsListener((target, windowInsets) -> {
                Insets safe = windowInsets.getInsets(
                        WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                target.setPadding(initialLeft + safe.left, initialTop + safe.top,
                        initialRight + safe.right, initialBottom + safe.bottom);
                return windowInsets;
            });
        }
        content.requestApplyInsets();
    }

    @Override
    public boolean dispatchTouchEvent(MotionEvent event) {
        if (!prepareTouchDispatch(getWindow(), event, activityTouchGate)) return false;
        return super.dispatchTouchEvent(event);
    }

    @Override
    public void onActionModeStarted(ActionMode mode) {
        super.onActionModeStarted(mode);
        View focused = getCurrentFocus();
        if (focused instanceof TextView textView) {
            selectionDismissal.started(textView, mode);
        }
    }

    @Override
    public void onActionModeFinished(ActionMode mode) {
        selectionDismissal.finished(mode);
        super.onActionModeFinished(mode);
    }

    protected final void enableReadOnlySelection(TextView textView) {
        if (textView instanceof EditText) {
            throw new IllegalArgumentException("Editable text requires its own selection policy");
        }
        textView.setTextIsSelectable(true);
        textView.setCustomSelectionActionModeCallback(new ActionMode.Callback() {
            @Override
            public boolean onCreateActionMode(ActionMode mode, Menu menu) {
                selectionDismissal.started(textView, mode);
                return true;
            }

            @Override
            public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
                return false;
            }

            @Override
            public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
                return false;
            }

            @Override
            public void onDestroyActionMode(ActionMode mode) {
                selectionDismissal.finished(textView, mode);
            }
        });
    }

    static void selectionStarted(TextView owner, ActionMode mode) {
        SecureActivity activity = find(owner.getContext());
        if (activity != null) activity.selectionDismissal.started(owner, mode);
    }

    static void selectionFinished(TextView owner, ActionMode mode) {
        SecureActivity activity = find(owner.getContext());
        if (activity != null) activity.selectionDismissal.finished(owner, mode);
    }

    static void installSelectionDismissal(Context context, Window window) {
        SecureActivity activity = find(context);
        if (activity == null) return;
        Window.Callback callback = window.getCallback();
        if (callback == null || callback instanceof SelectionWindowCallback) return;
        window.setCallback(new SelectionWindowCallback(activity, window, callback));
    }

    static void registerSensitiveText(EditText field) {
        SecureActivity activity = find(field.getContext());
        if (activity != null) activity.sensitiveText.add(field);
    }

    /** Registers a main-thread callback that is removed after it runs or is unregistered. */
    final boolean addForegroundLossObserver(Runnable observer) {
        if (!secureSessionActive || isFinishing() || isDestroyed()) return false;
        foregroundLossObservers.add(observer);
        return true;
    }

    final void removeForegroundLossObserver(Runnable observer) {
        foregroundLossObservers.remove(observer);
    }

    final boolean isSecureSessionActive() {
        return secureSessionActive && !isFinishing() && !isDestroyed();
    }

    /** Called only when every started Termux Vault Activity has left the foreground. */
    protected void onSecureForegroundLost() {}

    final void applicationForegroundLost() {
        endSecureSession(true);
    }

    final void applicationForegroundGained() {
        if (!isFinishing() && !isDestroyed()) secureSessionActive = true;
    }

    private void endSecureSession(boolean foregroundLost) {
        if (!secureSessionActive) return;
        secureSessionActive = false;
        List<Runnable> observers = new ArrayList<>(foregroundLossObservers);
        foregroundLossObservers.clear();
        for (Runnable observer : observers) observer.run();
        clearSensitiveText();
        selectionDismissal.finishAndCollapseTracked();
        if (foregroundLost) onSecureForegroundLost();
    }

    private void clearSensitiveText() {
        for (EditText field : new ArrayList<>(sensitiveText)) Ui.clear(field);
        sensitiveText.clear();
    }

    @Override
    protected void onDestroy() {
        endSecureSession(false);
        super.onDestroy();
    }

    private static SecureActivity find(Context context) {
        Context current = context;
        while (current != null) {
            if (current instanceof SecureActivity activity) return activity;
            if (!(current instanceof ContextWrapper wrapper)) return null;
            Context base = wrapper.getBaseContext();
            if (base == current) return null;
            current = base;
        }
        return null;
    }

    private void trackFocusedSelection(Window window, ActionMode mode) {
        View focused = window.getCurrentFocus();
        if (focused instanceof TextView textView) selectionDismissal.started(textView, mode);
    }

    private boolean prepareTouchDispatch(Window window, MotionEvent event,
                                         OccludedTouchGate touchGate) {
        int action = event.getActionMasked();
        boolean down = action == MotionEvent.ACTION_DOWN;
        SelectionDismissalController.Snapshot snapshot = down
                ? selectionDismissal.snapshot(window.getDecorView()) : null;
        int flags = event.getFlags();
        // Some firmware reports the app-owned floating selection UI as partial occlusion. Keep
        // rejecting partial occlusion by default; on Android 12+ (where this app also asks Android
        // to hide non-system overlays), the gate opens only for a DOWN backed by this window's
        // tracked text ActionMode and keeps that one pointer stream coherent through UP. Android
        // 11 lacks hide-overlay protection, so it retains the stricter historical policy.
        boolean reject = touchGate.shouldReject(
                down,
                action == MotionEvent.ACTION_UP || action == MotionEvent.ACTION_CANCEL,
                (flags & MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0,
                (flags & MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0,
                Build.VERSION.SDK_INT >= 31
                        && snapshot != null && snapshot.hasTrackedActionMode);
        if (reject) return false;
        if (snapshot != null) selectionDismissal.dismissOutside(snapshot, event);
        // Selection cleanup never consumes an accepted event. The original target receives the
        // same DOWN/MOVE/UP stream, so buttons, links, fields, and scrolling still work normally.
        return true;
    }

    private static final class SelectionDismissalController {
        private final IdentityHashMap<TextView, ActionMode> actionModes =
                new IdentityHashMap<>();

        void started(TextView selectedOwner, ActionMode selectedMode) {
            if (hasSelection(selectedOwner)) actionModes.put(selectedOwner, selectedMode);
        }

        void finished(ActionMode finishedMode) {
            Iterator<Map.Entry<TextView, ActionMode>> iterator = actionModes.entrySet().iterator();
            while (iterator.hasNext()) {
                if (iterator.next().getValue() == finishedMode) iterator.remove();
            }
        }

        void finished(TextView finishedOwner, ActionMode finishedMode) {
            if (actionModes.get(finishedOwner) == finishedMode) actionModes.remove(finishedOwner);
        }

        void finishAndCollapseTracked() {
            ArrayList<TextView> owners = new ArrayList<>(actionModes.size());
            ArrayList<ActionMode> modes = new ArrayList<>(actionModes.size());
            for (Map.Entry<TextView, ActionMode> entry : actionModes.entrySet()) {
                owners.add(entry.getKey());
                modes.add(entry.getValue());
            }
            actionModes.clear();
            for (int index = 0; index < owners.size(); index++) {
                TextView owner = owners.get(index);
                ActionMode mode = modes.get(index);
                if (mode != null) mode.finish();
                if (owner.isAttachedToWindow() && hasSelection(owner)) {
                    collapseSelection(owner, Math.min(
                            owner.getSelectionStart(), owner.getSelectionEnd()));
                }
            }
        }

        Snapshot snapshot(View root) {
            Iterator<TextView> tracked = actionModes.keySet().iterator();
            while (tracked.hasNext()) {
                TextView owner = tracked.next();
                if (!owner.isAttachedToWindow() || !hasSelection(owner)) tracked.remove();
            }
            ArrayList<TextView> live = new ArrayList<>();
            collectSelections(root, live);
            boolean hasTrackedActionMode = false;
            for (TextView owner : live) {
                if (actionModes.get(owner) != null) {
                    hasTrackedActionMode = true;
                    break;
                }
            }
            return new Snapshot(live, hasTrackedActionMode);
        }

        void dismissOutside(Snapshot snapshot, MotionEvent event) {
            for (TextView owner : snapshot.owners) {
                if (!owner.isAttachedToWindow() || !hasSelection(owner)) continue;
                if (containsSelectedText(owner, event.getRawX(), event.getRawY())) continue;

                int collapseAt = Math.min(owner.getSelectionStart(), owner.getSelectionEnd());
                ActionMode mode = actionModes.remove(owner);
                if (mode != null) mode.finish();
                collapseSelection(owner, collapseAt);
            }
        }

        private static void collectSelections(View view, List<TextView> output) {
            if (view instanceof TextView textView && hasSelection(textView)) {
                output.add(textView);
            }
            if (view instanceof ViewGroup group) {
                for (int index = 0; index < group.getChildCount(); index++) {
                    collectSelections(group.getChildAt(index), output);
                }
            }
        }

        private static boolean hasSelection(TextView view) {
            int start = view.getSelectionStart();
            int end = view.getSelectionEnd();
            return start >= 0 && end >= 0 && start != end;
        }

        private static void collapseSelection(TextView view, int position) {
            CharSequence value = view.getText();
            if (!(value instanceof Spannable spannable)) return;
            if (view instanceof EditText && position >= 0 && position <= value.length()) {
                Selection.setSelection(spannable, position);
            } else {
                Selection.removeSelection(spannable);
            }
        }

        private static boolean containsSelectedText(TextView view, float rawX, float rawY) {
            Layout layout = view.getLayout();
            if (layout == null) return false;
            int start = view.getSelectionStart();
            int end = view.getSelectionEnd();
            if (start < 0 || end < 0 || start == end) return false;

            Path selectedPath = new Path();
            layout.getSelectionPath(Math.min(start, end), Math.max(start, end), selectedPath);
            selectedPath.offset(view.getTotalPaddingLeft() - view.getScrollX(),
                    view.getTotalPaddingTop() - view.getScrollY());

            int[] location = new int[2];
            view.getLocationOnScreen(location);
            int localX = (int) Math.floor(rawX - location[0]);
            int localY = (int) Math.floor(rawY - location[1]);
            if (localX < 0 || localY < 0
                    || localX >= view.getWidth() || localY >= view.getHeight()) {
                return false;
            }

            Region clippedView = new Region(0, 0, view.getWidth(), view.getHeight());
            Region selectedRegion = new Region();
            return selectedRegion.setPath(selectedPath, clippedView)
                    && selectedRegion.contains(localX, localY);
        }

        private static final class Snapshot {
            final List<TextView> owners;
            final boolean hasTrackedActionMode;

            Snapshot(List<TextView> owners, boolean hasTrackedActionMode) {
                this.owners = owners;
                this.hasTrackedActionMode = hasTrackedActionMode;
            }
        }
    }

    /** Delegates a dialog Window while observing touch and action-mode events. */
    private static final class SelectionWindowCallback implements Window.Callback {
        private final SecureActivity activity;
        private final Window window;
        private final Window.Callback delegate;
        private final OccludedTouchGate touchGate = new OccludedTouchGate();

        SelectionWindowCallback(SecureActivity activity, Window window, Window.Callback delegate) {
            this.activity = activity;
            this.window = window;
            this.delegate = delegate;
        }

        @Override
        public boolean dispatchTouchEvent(MotionEvent event) {
            if (!activity.prepareTouchDispatch(window, event, touchGate)) return false;
            return delegate.dispatchTouchEvent(event);
        }

        @Override
        public void onActionModeStarted(ActionMode mode) {
            delegate.onActionModeStarted(mode);
            activity.trackFocusedSelection(window, mode);
        }

        @Override
        public void onActionModeFinished(ActionMode mode) {
            activity.selectionDismissal.finished(mode);
            delegate.onActionModeFinished(mode);
        }

        @Override
        public boolean dispatchGenericMotionEvent(MotionEvent event) {
            return delegate.dispatchGenericMotionEvent(event);
        }

        @Override
        public boolean dispatchKeyEvent(KeyEvent event) {
            return delegate.dispatchKeyEvent(event);
        }

        @Override
        public boolean dispatchKeyShortcutEvent(KeyEvent event) {
            return delegate.dispatchKeyShortcutEvent(event);
        }

        @Override
        public boolean dispatchPopulateAccessibilityEvent(AccessibilityEvent event) {
            return delegate.dispatchPopulateAccessibilityEvent(event);
        }

        @Override
        public boolean dispatchTrackballEvent(MotionEvent event) {
            return delegate.dispatchTrackballEvent(event);
        }

        @Override
        public void onAttachedToWindow() {
            delegate.onAttachedToWindow();
        }

        @Override
        public void onContentChanged() {
            delegate.onContentChanged();
        }

        @Override
        public boolean onCreatePanelMenu(int featureId, Menu menu) {
            return delegate.onCreatePanelMenu(featureId, menu);
        }

        @Override
        public View onCreatePanelView(int featureId) {
            return delegate.onCreatePanelView(featureId);
        }

        @Override
        public void onDetachedFromWindow() {
            delegate.onDetachedFromWindow();
        }

        @Override
        public boolean onMenuItemSelected(int featureId, MenuItem item) {
            return delegate.onMenuItemSelected(featureId, item);
        }

        @Override
        public boolean onMenuOpened(int featureId, Menu menu) {
            return delegate.onMenuOpened(featureId, menu);
        }

        @Override
        public void onPanelClosed(int featureId, Menu menu) {
            delegate.onPanelClosed(featureId, menu);
        }

        @Override
        public void onPointerCaptureChanged(boolean hasCapture) {
            delegate.onPointerCaptureChanged(hasCapture);
        }

        @Override
        public boolean onPreparePanel(int featureId, View view, Menu menu) {
            return delegate.onPreparePanel(featureId, view, menu);
        }

        @Override
        public void onProvideKeyboardShortcuts(List<KeyboardShortcutGroup> data, Menu menu,
                                               int deviceId) {
            delegate.onProvideKeyboardShortcuts(data, menu, deviceId);
        }

        @Override
        public boolean onSearchRequested() {
            return delegate.onSearchRequested();
        }

        @Override
        public boolean onSearchRequested(SearchEvent searchEvent) {
            return delegate.onSearchRequested(searchEvent);
        }

        @Override
        public void onWindowAttributesChanged(WindowManager.LayoutParams attributes) {
            delegate.onWindowAttributesChanged(attributes);
        }

        @Override
        public void onWindowFocusChanged(boolean hasFocus) {
            delegate.onWindowFocusChanged(hasFocus);
        }

        @Override
        public ActionMode onWindowStartingActionMode(ActionMode.Callback callback) {
            return delegate.onWindowStartingActionMode(callback);
        }

        @Override
        public ActionMode onWindowStartingActionMode(ActionMode.Callback callback, int type) {
            return delegate.onWindowStartingActionMode(callback, type);
        }
    }
}
