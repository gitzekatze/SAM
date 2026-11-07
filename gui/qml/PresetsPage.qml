// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs as Dialogs
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

import Appseal.Native

/// Preset manager (whitepaper §2.21.5): create, edit, duplicate, delete,
/// apply, import and export.
Kirigami.ScrollablePage {
    id: page
    title: qsTr("Presets")
    property var presets: []
    readonly property var win: QQC2.ApplicationWindow.window

    function reload() {
        Backend.call(["preset", "list"], function (r) {
            if (r.ok)
                page.presets = r.data
            else
                win.reportError(r)
        })
    }
    function edit(preset, isNew) {
        win.pageStack.push(Qt.resolvedUrl("PresetEditorPage.qml"), { preset: JSON.parse(JSON.stringify(preset)), isNew: !!isNew, onSaved: () => page.reload() })
    }
    function duplicate(p) {
        win.textDialog.ask(qsTr("Duplicate “%1”").arg(p.name), p.name + " " + qsTr("(copy)"), function (name) {
            Backend.call(["preset", "duplicate", p.name, name], function (r) {
                if (r.ok) win.notify(qsTr("Created “%1”").arg(name))
                else win.reportError(r)
                page.reload()
            })
        }, false, qsTr("Duplicate"))
    }

    Component.onCompleted: reload()

    actions: [
        Kirigami.Action {
            text: qsTr("New preset")
            icon.name: "list-add"
            onTriggered: {
                const base = page.presets.find(p => p.name === "Untrusted Utility") || page.presets[0]
                const p = JSON.parse(JSON.stringify(base))
                p.name = ""
                p.description = ""
                p.builtin = false
                p.compatibility_notes = ""
                p.created_at = 0
                page.edit(p, true)
            }
        },
        Kirigami.Action {
            text: qsTr("Import…")
            icon.name: "document-import"
            onTriggered: importDialog.open()
        }
    ]

    ListView {
        id: list
        model: page.presets
        spacing: Kirigami.Units.smallSpacing
        topMargin: Kirigami.Units.largeSpacing
        leftMargin: Kirigami.Units.largeSpacing
        rightMargin: Kirigami.Units.largeSpacing

        delegate: QQC2.ItemDelegate {
            id: card
            required property var modelData
            width: list.width - list.leftMargin - list.rightMargin
            padding: Kirigami.Units.largeSpacing
            onClicked: page.edit(modelData, false)
            background: Rectangle {
                radius: Kirigami.Units.cornerRadius
                color: card.hovered ? Qt.rgba(Kirigami.Theme.highlightColor.r, Kirigami.Theme.highlightColor.g, Kirigami.Theme.highlightColor.b, 0.10) : Kirigami.Theme.backgroundColor
                border.color: Qt.rgba(Kirigami.Theme.textColor.r, Kirigami.Theme.textColor.g, Kirigami.Theme.textColor.b, 0.12)
                Kirigami.Theme.colorSet: Kirigami.Theme.View
                Kirigami.Theme.inherit: false
            }
            contentItem: RowLayout {
                spacing: Kirigami.Units.largeSpacing
                Kirigami.Icon {
                    source: card.modelData.builtin ? "bookmarks" : "bookmark-new"
                    Layout.preferredWidth: Kirigami.Units.iconSizes.medium
                    Layout.preferredHeight: Kirigami.Units.iconSizes.medium
                }
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2
                    RowLayout {
                        Kirigami.Heading { level: 3; text: card.modelData.name; elide: Text.ElideRight; Layout.fillWidth: true }
                    }
                    QQC2.Label { text: card.modelData.description; opacity: 0.75; wrapMode: Text.Wrap; Layout.fillWidth: true }
                    Flow {
                        Layout.fillWidth: true
                        spacing: Kirigami.Units.smallSpacing
                        RiskChip { level: card.modelData.risk }
                        QQC2.Label {
                            text: card.modelData.builtin ? qsTr("Built-in") : qsTr("Modified %1").arg(Backend.formatTime(card.modelData.modified_at))
                            opacity: 0.6
                            font.pointSize: Math.max(7, Qt.application.font.pointSize - 1)
                        }
                    }
                }
                QQC2.ToolButton {
                    icon.name: "overflow-menu"
                    onClicked: menu.popup()
                    QQC2.Menu {
                        id: menu
                        QQC2.Menu {
                            title: qsTr("Apply to…")
                            enabled: (page.win.apps || []).length > 0
                            Repeater {
                                model: page.win.apps
                                delegate: QQC2.MenuItem {
                                    required property var modelData
                                    text: modelData.name
                                    onTriggered: page.win.applyPreset(card.modelData.name, modelData.id, null)
                                }
                            }
                        }
                        QQC2.MenuItem { text: card.modelData.builtin ? qsTr("View") : qsTr("Edit"); icon.name: "document-edit"; onTriggered: page.edit(card.modelData, false) }
                        QQC2.MenuItem { text: qsTr("Duplicate…"); icon.name: "edit-copy"; onTriggered: page.duplicate(card.modelData) }
                        QQC2.MenuItem {
                            text: qsTr("Export…")
                            icon.name: "document-export"
                            onTriggered: { exportDialog.presetName = card.modelData.name; exportDialog.open() }
                        }
                        QQC2.MenuItem {
                            text: qsTr("Delete")
                            icon.name: "edit-delete"
                            enabled: !card.modelData.builtin
                            onTriggered: page.win.confirmDialog.ask(qsTr("Delete “%1”?").arg(card.modelData.name), qsTr("Apps that use this preset keep their current permissions."), function () {
                                Backend.call(["preset", "delete", card.modelData.name], function (r) {
                                    if (!r.ok) page.win.reportError(r)
                                    page.reload()
                                })
                            }, qsTr("Delete"))
                        }
                    }
                }
            }
        }
    }

    Dialogs.FileDialog {
        id: importDialog
        title: qsTr("Import preset")
        nameFilters: [qsTr("Appseal presets (*.toml)"), qsTr("All files (*)")]
        onAccepted: Backend.call(["preset", "import", Backend.urlToPath(selectedFile)], function (r) {
            if (r.ok) page.win.notify(qsTr("Imported “%1”").arg(r.data.name))
            else page.win.reportError(r)
            page.reload()
        })
    }

    Dialogs.FileDialog {
        id: exportDialog
        property string presetName: ""
        title: qsTr("Export preset")
        fileMode: Dialogs.FileDialog.SaveFile
        defaultSuffix: "toml"
        nameFilters: [qsTr("Appseal presets (*.toml)")]
        currentFolder: Backend.pathToUrl(Backend.homeDir())
        onAccepted: Backend.call(["preset", "export", presetName, Backend.urlToPath(selectedFile)], function (r) {
            if (r.ok) page.win.notify(qsTr("Exported"))
            else page.win.reportError(r)
        })
    }
}
