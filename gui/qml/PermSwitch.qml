// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import org.kde.kirigamiaddons.formcard as FormCard

/// A boolean permission bound to `editor.perms[key]`. Reverts its visual
/// state immediately; the editor applies (or rejects) the change.
FormCard.FormSwitchDelegate {
    id: d
    required property string key
    required property var editor
    property string overrideText: ""
    property string overrideDescription: ""

    visible: editor.advanced || !editor.isAdvanced(key)
    text: overrideText || editor.titleOf(key)
    description: editor.describe(key, overrideDescription)
    checked: editor.value(key) === true
    enabled: editor.editable

    onToggled: {
        const want = checked
        checked = Qt.binding(() => d.editor.value(d.key) === true)
        d.editor.request(d.key, want)
    }
}
