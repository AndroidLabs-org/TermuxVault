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

final class CommandEditText extends EditText {
    private final ActionMode.Callback actionModeFilter = new ActionMode.Callback() {
        @Override
        public boolean onCreateActionMode(ActionMode mode, Menu menu) {
            SecureActivity.selectionStarted(CommandEditText.this, mode);
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
            SecureActivity.selectionFinished(CommandEditText.this, mode);
        }
    };

    CommandEditText(Context context) {
        super(context);
        protect();
    }

    CommandEditText(Context context, AttributeSet attrs) {
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
        return CommandEditorPolicy.blocks(item.getItemId(),
                intent == null ? null : intent.getAction());
    }

    @Override
    public boolean onTextContextMenuItem(int id) {
        if (id == android.R.id.copy || id == android.R.id.cut) {
            SensitiveClipboard.copySelection(this, id == android.R.id.cut);
            return true;
        }
        if (CommandEditorPolicy.blocks(id, null)) return true;
        return super.onTextContextMenuItem(id);
    }

    @Override
    public boolean onKeyShortcut(int keyCode, KeyEvent event) {
        if (event.isCtrlPressed() || event.isMetaPressed()) {
            if (keyCode == KeyEvent.KEYCODE_C || keyCode == KeyEvent.KEYCODE_X) {
                SensitiveClipboard.copySelection(this, keyCode == KeyEvent.KEYCODE_X);
                return true;
            }
        }
        return super.onKeyShortcut(keyCode, event);
    }

    @Override
    public boolean performAccessibilityAction(int action, Bundle arguments) {
        if (action == AccessibilityNodeInfo.ACTION_COPY
                || action == AccessibilityNodeInfo.ACTION_CUT) {
            SensitiveClipboard.copySelection(this, action == AccessibilityNodeInfo.ACTION_CUT);
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
