// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.kirigamiaddons.formcard as FormCard

import Appseal.Native

/// Create or edit a preset. Built-in presets are read-only.
Kirigami.ScrollablePage {
    id: page
    required property var preset
    property bool isNew: false
    property var onSaved: null
    property var evaluation: null
    readonly property bool readOnly: preset.builtin === true
    readonly property var win: QQC2.ApplicationWindow.window

    title: isNew ? qsTr("New preset") : preset.name

    function evaluate() {
        Backend.call(["evaluate"], function (r) {
            if (r.ok) page.evaluation = r.data
        }, JSON.stringify(preset.permissions))
    }
    function save() {
        const p = JSON.parse(JSON.stringify(preset))
        p.name = nameField.text.trim()
        p.description = descField.text.trim()
        p.compatibility_notes = notesField.text.trim()
        if (!p.name) {
            win.notify(qsTr("Give the preset a name"))
            return
        }
        Backend.call(["preset", "put"], function (r) {
            if (!r.ok) {
                win.reportError(r)
                return
            }
            win.notify(qsTr("Preset “%1” saved").arg(p.name))
            if (page.onSaved) page.onSaved()
            win.pageStack.pop()
        }, JSON.stringify(p))
    }

    Component.onCompleted: evaluate()

    actions: [
        Kirigami.Action {
            text: qsTr("Save")
            icon.name: "document-save"
            visible: !page.readOnly
            onTriggered: page.save()
        }
    ]

    ColumnLayout {
        spacing: 0

        Kirigami.InlineMessage {
            Layout.fillWidth: true
            Layout.margins: Kirigami.Units.largeSpacing * 2
            visible: page.readOnly
            type: Kirigami.MessageType.Information
            text: qsTr("Built-in presets cannot be changed. Duplicate it to make your own version.")
        }

        FormCard.FormHeader { title: qsTr("Preset") }
        FormCard.FormCard {
            FormCard.FormTextFieldDelegate { id: nameField; label: qsTr("Name"); text: page.preset.name; enabled: !page.readOnly && page.isNew }
            FormCard.FormTextFieldDelegate { id: descField; label: qsTr("Description"); text: page.preset.description; enabled: !page.readOnly }
            FormCard.FormTextFieldDelegate { id: notesField; label: qsTr("Compatibility notes"); text: page.preset.compatibility_notes || ""; enabled: !page.readOnly }
        }

        PermissionsEditor {
            Layout.fillWidth: true
            perms: page.preset.permissions
            evaluation: page.evaluation
            editable: !page.readOnly
            onEdited: newPerms => {
                const p = JSON.parse(JSON.stringify(page.preset))
                p.permissions = newPerms
                page.preset = p
                page.evaluate()
            }
        }
        Item { Layout.preferredHeight: Kirigami.Units.gridUnit * 2 }
    }
}
