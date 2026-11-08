// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs as Dialogs
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.kirigamiaddons.formcard as FormCard

import SAM.Native
import "Util.js" as Util

/// A string-list permission (folders, ports, bus names, variables), edited
/// inline: the entries, then a text field with an add button. Folders also
/// get a folder picker. Always visible; greyed out when it does not apply.
ColumnLayout {
    id: root
    required property string key
    required property var editor
    property bool folders: true
    property string placeholder: folders ? qsTr("Folder path, e.g. ~/Projects") : qsTr("Add an entry")
    property bool available: true

    readonly property var items: editor.value(key) || []

    spacing: 0
    opacity: available ? 1 : 0.55
    enabled: editor.editable && available

    function add(v) {
        v = String(v).trim()
        if (v && root.items.indexOf(v) < 0)
            root.editor.request(root.key, root.items.concat([v]))
    }

    FormCard.FormTextDelegate {
        text: editor.titleOf(root.key)
        description: editor.describe(root.key, "")
    }

    Repeater {
        model: root.items
        delegate: FormCard.AbstractFormDelegate {
            id: row
            required property string modelData
            required property int index
            Layout.fillWidth: true
            background: null
            contentItem: RowLayout {
                Kirigami.Icon {
                    source: root.folders ? "folder" : "code-context"
                    implicitWidth: Kirigami.Units.iconSizes.small
                    implicitHeight: implicitWidth
                }
                QQC2.Label {
                    text: Util.plain(row.modelData)
                    textFormat: Text.PlainText
                    Layout.fillWidth: true
                    elide: Text.ElideMiddle
                    font.family: root.folders ? Kirigami.Theme.defaultFont.family : "monospace"
                }
                QQC2.ToolButton {
                    icon.name: "list-remove"
                    onClicked: {
                        const v = root.items.slice()
                        v.splice(row.index, 1)
                        root.editor.request(root.key, v)
                    }
                    QQC2.ToolTip.visible: hovered
                    QQC2.ToolTip.text: qsTr("Remove")
                }
            }
        }
    }

    FormCard.AbstractFormDelegate {
        Layout.fillWidth: true
        background: null
        contentItem: RowLayout {
            QQC2.TextField {
                id: field
                Layout.fillWidth: true
                placeholderText: root.placeholder
                onAccepted: { root.add(text); text = "" }
            }
            QQC2.ToolButton {
                icon.name: "folder-open"
                visible: root.folders
                onClicked: folderDialog.open()
                QQC2.ToolTip.visible: hovered
                QQC2.ToolTip.text: qsTr("Choose a folder")
            }
            QQC2.Button {
                text: qsTr("Add")
                icon.name: "list-add"
                enabled: field.text.trim().length > 0
                onClicked: { root.add(field.text); field.text = "" }
            }
        }
    }

    Dialogs.FolderDialog {
        id: folderDialog
        currentFolder: Backend.pathToUrl(Backend.homeDir())
        onAccepted: root.add(Util.tildifyRaw(Backend.urlToPath(selectedFolder), Backend.homeDir()))
    }
}
