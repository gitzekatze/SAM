// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs as Dialogs
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

import SAM.Native
import "Util.js" as Util

/// Left column: where SAM looks for AppImages (pinned), then every AppImage
/// it found, sandboxed or not. Selecting one opens its settings on the right.
Kirigami.ScrollablePage {
    id: page
    title: "SAM"

    readonly property var win: QQC2.ApplicationWindow.window
    readonly property var cfg: win ? win.config : null
    property string search: ""

    /// Locations: folders and single files, as stored in the config.
    readonly property var locations: {
        if (!cfg)
            return []
        const dirs = (cfg.general.scan_directories || []).map(p => ({ path: p, file: false }))
        const files = (cfg.general.scan_files || []).map(p => ({ path: p, file: true }))
        return dirs.concat(files)
    }

    /// One row per AppImage: found files merged with sandboxed apps.
    readonly property var rows: {
        if (!win)
            return []
        const apps = win.apps || []
        const out = []
        const seen = {}
        for (const d of (win.discovered || [])) {
            const a = d.sandboxed ? apps.find(x => x.id === d.sandboxed) : null
            out.push({
                key: a ? a.id : d.path,
                id: a ? a.id : "",
                path: d.path,
                name: a ? a.name : d.name,
                comment: a ? a.comment : d.comment,
                icon: (a && a.icon_path) ? a.icon_path : (d.icon || ""),
                sandboxed: !!a,
                badge: a ? a.badge : "",
                problem: a ? (a.last_problem || "") : "",
                unsandboxedEntry: (d.menu_entries || []).length > 0,
                moved: !!d.moved_from
            })
            if (a)
                seen[a.id] = true
        }
        // Sandboxed apps whose AppImage file is missing.
        for (const a of apps) {
            if (!seen[a.id])
                out.push({ key: a.id, id: a.id, path: a.source_path, name: a.name, comment: a.comment, icon: a.icon_path || "",
                           sandboxed: true, badge: a.badge, problem: a.last_problem || "", unsandboxedEntry: false, moved: false })
        }
        const q = search.toLowerCase()
        const filtered = q ? out.filter(r => (r.name || "").toLowerCase().indexOf(q) >= 0 || (r.path || "").toLowerCase().indexOf(q) >= 0) : out
        filtered.sort((x, y) => (x.name || "").toLowerCase().localeCompare((y.name || "").toLowerCase()))
        return filtered
    }

    function setLocations(dirs, files) {
        win.setConfig("general.scan_directories", dirs, () => win.setConfig("general.scan_files", files, () => win.refreshApps()))
    }
    function removeLocation(loc) {
        const dirs = (cfg.general.scan_directories || []).filter(p => loc.file || p !== loc.path)
        const files = (cfg.general.scan_files || []).filter(p => !loc.file || p !== loc.path)
        setLocations(dirs, files)
    }
    function addFolder(path) {
        const p = Util.tildifyRaw(path, win.home)
        const dirs = (cfg.general.scan_directories || []).slice()
        if (dirs.indexOf(p) < 0)
            dirs.push(p)
        setLocations(dirs, cfg.general.scan_files || [])
    }
    function addFile(path) {
        const p = Util.tildifyRaw(path, win.home)
        const files = (cfg.general.scan_files || []).slice()
        if (files.indexOf(p) < 0)
            files.push(p)
        setLocations(cfg.general.scan_directories || [], files)
    }

    actions: [
        Kirigami.Action {
            text: qsTr("Refresh")
            icon.name: "view-refresh"
            displayHint: Kirigami.DisplayHint.IconOnly
            onTriggered: win.refreshApps()
        },
        Kirigami.Action {
            text: qsTr("SAM settings")
            icon.name: "configure"
            displayHint: Kirigami.DisplayHint.AlwaysHide
            onTriggered: win.showSection("settings")
        },
        Kirigami.Action {
            text: qsTr("Presets")
            icon.name: "bookmarks"
            displayHint: Kirigami.DisplayHint.AlwaysHide
            onTriggered: win.showSection("presets")
        },
        Kirigami.Action {
            text: qsTr("Diagnostics")
            icon.name: "tools-report-bug"
            displayHint: Kirigami.DisplayHint.AlwaysHide
            onTriggered: win.showSection("diagnostics")
        }
    ]

    // ------------------------------------------------ pinned: locations
    header: QQC2.Pane {
        implicitHeight: win ? win.topHeight : Kirigami.Units.gridUnit * 9
        padding: Kirigami.Units.largeSpacing
        Kirigami.Theme.colorSet: Kirigami.Theme.Window
        Kirigami.Theme.inherit: false
        background: Rectangle {
            color: Kirigami.Theme.backgroundColor
            Kirigami.Separator { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom }
        }

        contentItem: ColumnLayout {
            spacing: Kirigami.Units.smallSpacing
            RowLayout {
                Kirigami.Heading {
                    level: 4
                    text: qsTr("AppImage locations")
                    Layout.fillWidth: true
                }
                QQC2.ToolButton {
                    icon.name: "folder-new"
                    text: qsTr("Folder")
                    display: QQC2.AbstractButton.TextBesideIcon
                    onClicked: folderDialog.open()
                    QQC2.ToolTip.visible: hovered
                    QQC2.ToolTip.text: qsTr("Search a folder for AppImages")
                }
                QQC2.ToolButton {
                    icon.name: "document-open"
                    text: qsTr("File")
                    display: QQC2.AbstractButton.TextBesideIcon
                    onClicked: fileDialog.open()
                    QQC2.ToolTip.visible: hovered
                    QQC2.ToolTip.text: qsTr("Add a single AppImage file")
                }
            }
            ListView {
                id: locList
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                model: page.locations
                QQC2.ScrollBar.vertical: QQC2.ScrollBar {}
                delegate: RowLayout {
                    required property var modelData
                    width: locList.width
                    spacing: Kirigami.Units.smallSpacing
                    Kirigami.Icon {
                        source: modelData.file ? "package-x-generic" : "folder"
                        implicitWidth: Kirigami.Units.iconSizes.small
                        implicitHeight: implicitWidth
                    }
                    QQC2.Label {
                        text: Util.plain(modelData.path)
                        textFormat: Text.PlainText
                        elide: Text.ElideMiddle
                        Layout.fillWidth: true
                    }
                    QQC2.ToolButton {
                        icon.name: "list-remove"
                        implicitHeight: Kirigami.Units.iconSizes.medium
                        implicitWidth: implicitHeight
                        onClicked: page.removeLocation(modelData)
                        QQC2.ToolTip.visible: hovered
                        QQC2.ToolTip.text: qsTr("Stop searching here")
                    }
                }
                QQC2.Label {
                    anchors.centerIn: parent
                    visible: locList.count === 0
                    text: qsTr("No locations yet: add a folder or a file.")
                    opacity: 0.6
                }
            }
            QQC2.Switch {
                text: qsTr("Also search the Downloads folder")
                checked: page.cfg !== null && page.cfg.general.scan_downloads === true
                onToggled: win.setConfig("general.scan_downloads", checked ? "true" : "false", () => win.refreshApps())
            }
        }
    }

    // ------------------------------------------------ app list
    ListView {
        id: list
        model: page.rows
        currentIndex: -1
        headerPositioning: ListView.InlineHeader
        header: Kirigami.SearchField {
            width: list.width - Kirigami.Units.largeSpacing * 2
            x: Kirigami.Units.largeSpacing
            placeholderText: qsTr("Search %1 AppImages…").arg(page.rows.length)
            onTextChanged: page.search = text
        }

        delegate: QQC2.ItemDelegate {
            id: row
            required property var modelData
            width: list.width
            highlighted: win !== null && win.selectedKey === modelData.key
            padding: Kirigami.Units.largeSpacing
            onClicked: win.selectRow(modelData)

            contentItem: RowLayout {
                spacing: Kirigami.Units.largeSpacing
                AppIcon {
                    path: row.modelData.icon
                    Layout.preferredWidth: Kirigami.Units.iconSizes.large
                    Layout.preferredHeight: Kirigami.Units.iconSizes.large
                }
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 1
                    QQC2.Label {
                        text: Util.plain(row.modelData.name)
                        textFormat: Text.PlainText
                        font.bold: true
                        elide: Text.ElideRight
                        Layout.fillWidth: true
                    }
                    QQC2.Label {
                        text: Util.tildify(row.modelData.path, win ? win.home : "")
                        textFormat: Text.PlainText
                        elide: Text.ElideMiddle
                        opacity: 0.65
                        font.pointSize: Math.max(7, Qt.application.font.pointSize - 1)
                        Layout.fillWidth: true
                    }
                    RowLayout {
                        spacing: Kirigami.Units.smallSpacing
                        Kirigami.Icon {
                            source: row.modelData.sandboxed ? "security-high" : "security-low"
                            color: row.highlighted ? Kirigami.Theme.highlightedTextColor : (row.modelData.sandboxed ? Kirigami.Theme.positiveTextColor : Kirigami.Theme.disabledTextColor)
                            implicitWidth: Kirigami.Units.iconSizes.small
                            implicitHeight: implicitWidth
                        }
                        QQC2.Label {
                            text: row.modelData.sandboxed
                                ? (row.modelData.badge === "missing" ? qsTr("Sandboxed · file missing") : qsTr("Sandboxed"))
                                : (row.modelData.moved ? qsTr("Moved copy of a sandboxed app") : qsTr("Not sandboxed"))
                            font.pointSize: Math.max(7, Qt.application.font.pointSize - 1)
                            color: row.highlighted ? Kirigami.Theme.highlightedTextColor : (row.modelData.sandboxed ? Kirigami.Theme.positiveTextColor : Kirigami.Theme.textColor)
                            opacity: row.modelData.sandboxed || row.highlighted ? 1 : 0.7
                        }
                        Kirigami.Icon {
                            visible: row.modelData.problem !== "" || row.modelData.unsandboxedEntry
                            source: "dialog-warning"
                            color: Kirigami.Theme.neutralTextColor
                            implicitWidth: Kirigami.Units.iconSizes.small
                            implicitHeight: implicitWidth
                            HoverHandler { id: warnHover }
                            QQC2.ToolTip.visible: warnHover.hovered
                            QQC2.ToolTip.text: row.modelData.problem !== ""
                                ? qsTr("Didn't work last time: %1").arg(Util.plain(row.modelData.problem))
                                : qsTr("Has an unsandboxed menu entry")
                        }
                    }
                }
            }
        }

        Kirigami.PlaceholderMessage {
            anchors.centerIn: parent
            width: parent.width - Kirigami.Units.gridUnit * 2
            visible: win !== null && win.appsLoaded && list.count === 0
            icon.name: "application-x-executable"
            text: page.search ? qsTr("No AppImages match") : qsTr("No AppImages found")
            explanation: page.search ? "" : qsTr("Add a folder or a single AppImage file above, or drop an AppImage onto this window.")
        }
    }

    Dialogs.FolderDialog {
        id: folderDialog
        title: qsTr("Search a folder for AppImages")
        currentFolder: Backend.pathToUrl(Backend.homeDir())
        onAccepted: page.addFolder(Backend.urlToPath(selectedFolder))
    }
    Dialogs.FileDialog {
        id: fileDialog
        title: qsTr("Add an AppImage")
        nameFilters: [qsTr("AppImages (*.AppImage *.appimage)"), qsTr("All files (*)")]
        currentFolder: Backend.pathToUrl(Backend.homeDir())
        onAccepted: page.addFile(Backend.urlToPath(selectedFile))
    }
}
