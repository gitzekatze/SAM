// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import org.kde.kirigamiaddons.formcard as FormCard

/// An enumerated permission, e.g. network.mode or a folder access level.
FormCard.FormComboBoxDelegate {
    id: d
    required property string key
    required property var editor
    /// [{ value: "none", text: "No access" }, ...]
    required property var options
    property string overrideText: ""
    property string overrideDescription: ""

    /// Greyed out (never hidden) when it does not apply, e.g. ~/.ssh
    /// without full home access.
    property bool available: true
    opacity: available ? 1 : 0.55
    text: overrideText || editor.titleOf(key)
    description: editor.describe(key, overrideDescription)
    model: options
    textRole: "text"
    valueRole: "value"
    enabled: editor.editable && available
    // Bind after the model is set: the inner ComboBox resets its index on model changes.
    Component.onCompleted: currentIndex = Qt.binding(() => d.indexFor(d.editor.value(d.key)))

    function indexFor(v) {
        for (let i = 0; i < options.length; i++)
            if (options[i].value === v)
                return i
        return 0
    }

    onActivated: function (index) {
        const want = options[index].value
        currentIndex = Qt.binding(() => d.indexFor(d.editor.value(d.key)))
        d.editor.request(d.key, want)
    }
}
