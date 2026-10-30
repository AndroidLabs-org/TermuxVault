package app.termuxvault.secure;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.AttributeSet;
import android.view.ActionMode;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.ViewStructure;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.EditText;

final class SecureEditText extends EditText {
    private final ActionMode.Callback actionModeFilter = new ActionMode.Callback() {
        @Override
        public boolean onCreateActionMode(ActionMode mode, Menu menu) {
            SecureActivity.selectionStarted(SecureEditText.this, mode);
            filterMenu(menu);
            return true;
        }

        @Override
        public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
            filterMenu(menu);
            return true;
        }

        @Override
        public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
            return isBlocked(item);
        }

        @Override
        public void onDestroyActionMode(ActionMode mode) {
            SecureActivity.selectionFinished(SecureEditText.this, mode);
        }
    };

    SecureEditText(Context context) {
        super(context);
        protect();
    }

    SecureEditText(Context context, AttributeSet attrs) {
        super(context, attrs);
        protect();
    }

    private void protect() {
        SensitiveViewProtection.configure(this);
        setCustomSelectionActionModeCallback(actionModeFilter);
        setCustomInsertionActionModeCallback(actionModeFilter);
    }

    private static void filterMenu(Menu menu) {
        for (int index = menu.size() - 1; index >= 0; index--) {
            MenuItem item = menu.getItem(index);
            if (isBlocked(item)) item.setEnabled(false).setVisible(false);
        }
    }

    private static boolean isBlocked(MenuItem item) {
        Intent intent = item.getIntent();
        return SecureTextActionPolicy.blocks(item.getItemId(),
                intent == null ? null : intent.getAction());
    }

    @Override
    public boolean onTextContextMenuItem(int id) {
        if (SecureTextActionPolicy.blocks(id, null)) return true;
        return super.onTextContextMenuItem(id);
    }

    @Override
    public boolean onKeyShortcut(int keyCode, KeyEvent event) {
        if ((event.isCtrlPressed() || event.isMetaPressed())
                && (keyCode == KeyEvent.KEYCODE_C || keyCode == KeyEvent.KEYCODE_X)) {
            return true;
        }
        return super.onKeyShortcut(keyCode, event);
    }

    @Override
    public boolean performAccessibilityAction(int action, Bundle arguments) {
        if (action == AccessibilityNodeInfo.ACTION_COPY
                || action == AccessibilityNodeInfo.ACTION_CUT) {
            return true;
        }
        return super.performAccessibilityAction(action, arguments);
    }

    @Override
    public void onProvideStructure(ViewStructure structure) {
        SensitiveViewProtection.redactStructure(structure);
    }

    @Override
    public void onProvideAutofillStructure(ViewStructure structure, int flags) {
        SensitiveViewProtection.redactStructure(structure);
    }

    @Override
    public void onProvideContentCaptureStructure(ViewStructure structure, int flags) {
        SensitiveViewProtection.redactStructure(structure);
    }
}
