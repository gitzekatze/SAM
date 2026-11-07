// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import org.kde.kirigami as Kirigami

/// Generic confirmation for risky actions. Call `ask(title, text, onYes, yesLabel)`.
Kirigami.PromptDialog {
    id: root
    property var onYes: null
    property string yesText: qsTr("Continue")

    standardButtons: Kirigami.Dialog.NoButton
    customFooterActions: [
        Kirigami.Action {
            text: root.yesText
            icon.name: "dialog-warning"
            onTriggered: {
                const cb = root.onYes
                root.close()
                if (cb)
                    cb()
            }
        },
        Kirigami.Action {
            text: qsTr("Cancel")
            icon.name: "dialog-cancel"
            onTriggered: root.close()
        }
    ]

    function ask(title, text, cb, yes) {
        root.title = title
        root.subtitle = text
        root.onYes = cb
        root.yesText = yes || qsTr("Continue")
        root.open()
    }
}
