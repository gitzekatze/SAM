// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs as Dialogs
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.kirigamiaddons.formcard as FormCard

import SAM.Native
import "Util.js" as Util

/// Edits a string list permission (custom folders, D-Bus names, ...).
ColumnLayout {
    id: root
    required property string key
    required property var editor
    property bool folders: true
    property string addText: folders ? qsTr("Add folder…") : qsTr("Add…")
    property string promptTitle: qsTr("Add entry")

    readonly property var items: editor.value(key) || []

    visible: editor.advanced || !editor.isAdvanced(key)
    spacing: 0

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
                    text: row.modelData
                    Layout.fillWidth: true
                    elide: Text.ElideMiddle
                    font.family: root.folders ? Kirigami.Theme.defaultFont.family : "monospace"
                }
                QQC2.ToolButton {
                    icon.name: "list-remove"
                    enabled: root.editor.editable
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

    FormCard.FormButtonDelegate {
        text: root.addText
        icon.name: "list-add"
        enabled: root.editor.editable
        onClicked: {
            if (root.folders)
                folderDialog.open()
            else
                applicationWindow().textDialog.ask(root.promptTitle, "", function (name) {
                    root.editor.request(root.key, root.items.concat([name]))
                }, false, qsTr("Add"))
        }
    }

    Dialogs.FolderDialog {
        id: folderDialog
        currentFolder: Backend.pathToUrl(Backend.homeDir())
        onAccepted: {
            const p = Util.tildify(Backend.urlToPath(selectedFolder), Backend.homeDir())
            if (root.items.indexOf(p) < 0)
                root.editor.request(root.key, root.items.concat([p]))
        }
    }
}
