// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

/// Ask for a name (and optional description), e.g. "Save as Preset".
Kirigami.Dialog {
    id: root
    property bool withDescription: false
    property var onDone: null
    property string acceptText: qsTr("Save")

    standardButtons: Kirigami.Dialog.NoButton
    padding: Kirigami.Units.largeSpacing
    preferredWidth: Kirigami.Units.gridUnit * 22

    function ask(title, name, cb, withDesc, accept) {
        root.title = title
        nameField.text = name || ""
        descField.text = ""
        root.withDescription = !!withDesc
        root.onDone = cb
        root.acceptText = accept || qsTr("Save")
        root.open()
        nameField.forceActiveFocus()
    }

    customFooterActions: [
        Kirigami.Action {
            text: root.acceptText
            icon.name: "document-save"
            enabled: nameField.text.trim().length > 0
            onTriggered: {
                const cb = root.onDone
                root.close()
                if (cb)
                    cb(nameField.text.trim(), descField.text.trim())
            }
        },
        Kirigami.Action {
            text: qsTr("Cancel")
            icon.name: "dialog-cancel"
            onTriggered: root.close()
        }
    ]

    ColumnLayout {
        spacing: Kirigami.Units.smallSpacing
        QQC2.Label { text: qsTr("Name") }
        QQC2.TextField {
            id: nameField
            Layout.fillWidth: true
            onAccepted: if (text.trim().length > 0) root.customFooterActions[0].trigger()
        }
        QQC2.Label { text: qsTr("Description"); visible: root.withDescription }
        QQC2.TextField {
            id: descField
            Layout.fillWidth: true
            visible: root.withDescription
        }
    }
}
