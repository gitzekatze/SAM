// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

import SAM.Native
import "Util.js" as Util

/// Overview: every AppImage SAM found, sandboxed or not (like Flatseal's
/// app list). Sandboxed apps come first; the others offer "Create sandbox".
Kirigami.ScrollablePage {
    id: page
    title: qsTr("Applications")

    property string search: ""
    property string badgeFilter: ""
    property string riskFilter: ""
    property string categoryFilter: ""
    property string sortMode: "name"
    readonly property var win: QQC2.ApplicationWindow.window
    readonly property var allApps: win ? (win.apps || []) : []
    /// Found AppImages without a sandbox (sandboxed ones are in allApps).
    readonly property var unsandboxed: win ? (win.discovered || []).filter(d => !d.sandboxed) : []

    readonly property var filtered: {
        let list = page.allApps.slice()
        const q = search.toLowerCase()
        if (q)
            list = list.filter(a => a.name.toLowerCase().indexOf(q) >= 0 || a.id.indexOf(q) >= 0 || (a.comment || "").toLowerCase().indexOf(q) >= 0)
        if (badgeFilter)
            list = list.filter(a => a.badge === badgeFilter)
        if (riskFilter)
            list = list.filter(a => a.risk.level === riskFilter)
        if (categoryFilter)
            list = list.filter(a => a.category === categoryFilter)
        if (sortMode === "recent")
            list.sort((a, b) => (b.last_launched || 0) - (a.last_launched || 0))
        else if (sortMode === "added")
            list.sort((a, b) => b.added_at - a.added_at)
        else if (sortMode === "risk")
            list.sort((a, b) => b.risk.score - a.risk.score)
        return list.map(a => Object.assign({ group: "sandboxed" }, a))
    }
    readonly property var filteredFound: {
        // Status and risk only exist for sandboxed apps.
        if (badgeFilter || riskFilter)
            return []
        let list = page.unsandboxed.slice()
        const q = search.toLowerCase()
        if (q)
            list = list.filter(d => d.name.toLowerCase().indexOf(q) >= 0 || (d.comment || "").toLowerCase().indexOf(q) >= 0 || d.path.toLowerCase().indexOf(q) >= 0)
        if (categoryFilter)
            list = list.filter(d => d.category === categoryFilter)
        return list.map(d => Object.assign({ group: "found" }, d))
    }
    readonly property var rows: page.filtered.concat(page.filteredFound)
    readonly property var attention: page.allApps.filter(a => a.badge !== "ready")

    actions: [
        Kirigami.Action {
            text: qsTr("Sandbox a file…")
            icon.name: "list-add"
            onTriggered: applicationWindow().addDialog.open()
        },
        Kirigami.Action {
            text: qsTr("Refresh")
            icon.name: "view-refresh"
            onTriggered: applicationWindow().refreshApps()
        },
        Kirigami.Action {
            text: qsTr("Check for changes")
            icon.name: "view-refresh"
            displayHint: Kirigami.DisplayHint.AlwaysHide
            onTriggered: Backend.call(["refresh"], function (r) {
                applicationWindow().refreshApps()
                if (r.ok) {
                    const changed = r.data.filter(i => i.status === "stale" || i.status === "missing")
                    applicationWindow().notify(changed.length ? qsTr("%1 app(s) changed or went missing").arg(changed.length) : qsTr("All AppImages are unchanged"))
                }
            })
        }
    ]

    header: QQC2.ToolBar {
        visible: page.allApps.length + page.unsandboxed.length > 0
        contentItem: Flow {
            spacing: Kirigami.Units.smallSpacing
            Kirigami.SearchField {
                width: Math.min(Kirigami.Units.gridUnit * 16, page.width - Kirigami.Units.gridUnit * 2)
                placeholderText: qsTr("Search apps…")
                onTextChanged: page.search = text
            }
            QQC2.ComboBox {
                model: [
                    { text: qsTr("Any status"), value: "" },
                    { text: qsTr("Ready"), value: "ready" },
                    { text: qsTr("Needs Review"), value: "needs-review" },
                    { text: qsTr("Compatibility Risk"), value: "compatibility-risk" },
                    { text: qsTr("Stale"), value: "stale" },
                    { text: qsTr("Broken"), value: "broken" },
                    { text: qsTr("Unsafe"), value: "unsafe" },
                    { text: qsTr("Missing"), value: "missing" }
                ]
                textRole: "text"
                valueRole: "value"
                onActivated: page.badgeFilter = currentValue
            }
            QQC2.ComboBox {
                model: [
                    { text: qsTr("Any risk"), value: "" },
                    { text: qsTr("Low risk"), value: "low" },
                    { text: qsTr("Medium risk"), value: "medium" },
                    { text: qsTr("High risk"), value: "high" },
                    { text: qsTr("Dangerous"), value: "dangerous" }
                ]
                textRole: "text"
                valueRole: "value"
                onActivated: page.riskFilter = currentValue
            }
            QQC2.ComboBox {
                model: [{ text: qsTr("Any category"), value: "" }].concat(Object.keys(Util.categoryLabels).map(k => ({ text: Util.categoryLabels[k], value: k })))
                textRole: "text"
                valueRole: "value"
                onActivated: page.categoryFilter = currentValue
            }
            QQC2.ComboBox {
                model: [
                    { text: qsTr("Sort by name"), value: "name" },
                    { text: qsTr("Recently used"), value: "recent" },
                    { text: qsTr("Recently added"), value: "added" },
                    { text: qsTr("Highest risk"), value: "risk" }
                ]
                textRole: "text"
                valueRole: "value"
                onActivated: page.sortMode = currentValue
            }
        }
    }

    ListView {
        id: list
        model: page.rows
        spacing: Kirigami.Units.smallSpacing
        section.property: "group"
        section.delegate: Kirigami.ListSectionHeader {
            required property string section
            width: list.width - list.leftMargin - list.rightMargin
            text: section === "sandboxed" ? qsTr("Sandboxed (%1)").arg(page.filtered.length) : qsTr("Not sandboxed (%1)").arg(page.filteredFound.length)
        }
        topMargin: Kirigami.Units.largeSpacing
        bottomMargin: Kirigami.Units.largeSpacing
        leftMargin: Kirigami.Units.largeSpacing
        rightMargin: Kirigami.Units.largeSpacing

        headerPositioning: ListView.InlineHeader
        header: ColumnLayout {
            width: list.width - list.leftMargin - list.rightMargin
            visible: page.attention.length > 0 && !page.badgeFilter
            height: visible ? implicitHeight + Kirigami.Units.largeSpacing : 0
            Kirigami.InlineMessage {
                Layout.fillWidth: true
                visible: parent.visible
                type: page.attention.some(a => a.badge === "broken" || a.badge === "unsafe" || a.badge === "missing") ? Kirigami.MessageType.Warning : Kirigami.MessageType.Information
                text: qsTr("%n app(s) need your attention.", "", page.attention.length)
                actions: [
                    Kirigami.Action {
                        text: qsTr("Show them")
                        onTriggered: page.badgeFilter = page.attention[0].badge
                    }
                ]
            }
        }

        delegate: Loader {
            required property var modelData
            width: list.width - list.leftMargin - list.rightMargin
            sourceComponent: modelData.group === "found" ? foundCard : appCard
            onLoaded: item.modelData = Qt.binding(() => modelData)
        }

        Component {
            id: appCard
        QQC2.ItemDelegate {
            id: card
            property var modelData: ({})
            width: parent ? parent.width : 0
            padding: Kirigami.Units.largeSpacing
            onClicked: applicationWindow().openApp(modelData.id)

            background: Rectangle {
                radius: Kirigami.Units.cornerRadius
                color: card.hovered ? Qt.rgba(Kirigami.Theme.highlightColor.r, Kirigami.Theme.highlightColor.g, Kirigami.Theme.highlightColor.b, 0.10) : Kirigami.Theme.backgroundColor
                border.color: Qt.rgba(Kirigami.Theme.textColor.r, Kirigami.Theme.textColor.g, Kirigami.Theme.textColor.b, 0.12)
                Kirigami.Theme.colorSet: Kirigami.Theme.View
                Kirigami.Theme.inherit: false
            }

            contentItem: RowLayout {
                spacing: Kirigami.Units.largeSpacing
                AppIcon {
                    path: card.modelData.icon_path || ""
                    Layout.preferredWidth: Kirigami.Units.iconSizes.large
                    Layout.preferredHeight: Kirigami.Units.iconSizes.large
                }
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2
                    RowLayout {
                        Kirigami.Heading {
                            level: 3
                            text: card.modelData.name
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }
                    }
                    QQC2.Label {
                        Layout.fillWidth: true
                        text: card.modelData.comment || Util.categoryLabel(card.modelData.category)
                        elide: Text.ElideRight
                        opacity: 0.75
                    }
                    Flow {
                        Layout.fillWidth: true
                        spacing: Kirigami.Units.smallSpacing
                        StatusBadge { badge: card.modelData.badge }
                        RiskChip { level: card.modelData.risk.level; compact: false }
                        QQC2.Label {
                            text: Util.categoryLabel(card.modelData.category) + " · " + qsTr("Last run: %1").arg(Backend.formatTime(card.modelData.last_launched || 0))
                            opacity: 0.6
                            font.pointSize: Math.max(7, Qt.application.font.pointSize - 1)
                            height: parent.children[0].height
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                }
                QQC2.Button {
                    text: qsTr("Run")
                    icon.name: "media-playback-start"
                    enabled: card.modelData.badge !== "missing"
                    onClicked: applicationWindow().launch(card.modelData.id)
                    QQC2.ToolTip.visible: hovered
                    QQC2.ToolTip.text: qsTr("Start %1 in its sandbox").arg(card.modelData.name)
                }
                QQC2.ToolButton {
                    icon.name: "configure"
                    onClicked: applicationWindow().openApp(card.modelData.id)
                    QQC2.ToolTip.visible: hovered
                    QQC2.ToolTip.text: qsTr("Configure")
                }
            }
        }
        }

        Component {
            id: foundCard
            QQC2.ItemDelegate {
                id: fcard
                property var modelData: ({ menu_entries: [] })
                width: parent ? parent.width : 0
                padding: Kirigami.Units.largeSpacing
                hoverEnabled: false

                background: Rectangle {
                    radius: Kirigami.Units.cornerRadius
                    color: Kirigami.Theme.backgroundColor
                    border.color: Qt.rgba(Kirigami.Theme.textColor.r, Kirigami.Theme.textColor.g, Kirigami.Theme.textColor.b, 0.12)
                    Kirigami.Theme.colorSet: Kirigami.Theme.View
                    Kirigami.Theme.inherit: false
                }

                contentItem: RowLayout {
                    spacing: Kirigami.Units.largeSpacing
                    AppIcon {
                        path: fcard.modelData.icon || ""
                        Layout.preferredWidth: Kirigami.Units.iconSizes.large
                        Layout.preferredHeight: Kirigami.Units.iconSizes.large
                        opacity: 0.85
                    }
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2
                        Kirigami.Heading {
                            level: 3
                            text: fcard.modelData.name || ""
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }
                        QQC2.Label {
                            Layout.fillWidth: true
                            text: fcard.modelData.comment || fcard.modelData.category_label || ""
                            elide: Text.ElideRight
                            opacity: 0.75
                        }
                        Flow {
                            Layout.fillWidth: true
                            spacing: Kirigami.Units.smallSpacing
                            Kirigami.Chip {
                                text: fcard.modelData.moved_from ? qsTr("Moved copy of a sandboxed app") : qsTr("Not sandboxed")
                                icon.name: fcard.modelData.moved_from ? "document-swap" : "security-low"
                                closable: false
                                checkable: false
                            }
                            Kirigami.Chip {
                                visible: (fcard.modelData.menu_entries || []).length > 0
                                text: qsTr("Unsandboxed menu entry")
                                icon.name: "dialog-warning"
                                closable: false
                                checkable: false
                                QQC2.ToolTip.visible: hovered
                                QQC2.ToolTip.text: qsTr("Starting it from the menu runs it without any sandbox.")
                            }
                            QQC2.Label {
                                text: (fcard.modelData.category_label || "") + " · " + Util.tildify(fcard.modelData.path || "", page.win ? page.win.home : "")
                                opacity: 0.6
                                font.pointSize: Math.max(7, Qt.application.font.pointSize - 1)
                                elide: Text.ElideMiddle
                                width: Math.min(implicitWidth, fcard.width * 0.6)
                            }
                        }
                    }
                    QQC2.Button {
                        text: fcard.modelData.moved_from ? qsTr("Reconnect") : qsTr("Create sandbox")
                        icon.name: fcard.modelData.moved_from ? "document-swap" : "security-high"
                        onClicked: applicationWindow().createSandbox(fcard.modelData.path)
                        QQC2.ToolTip.visible: hovered
                        QQC2.ToolTip.text: fcard.modelData.moved_from
                            ? qsTr("Point the existing sandbox at this file")
                            : qsTr("Unpack %1 (without running it), recommend permissions and add a sandboxed menu entry").arg(fcard.modelData.name)
                    }
                }
            }
        }

        Kirigami.PlaceholderMessage {
            anchors.centerIn: parent
            width: parent.width - Kirigami.Units.gridUnit * 4
            readonly property bool anything: page.allApps.length + page.unsandboxed.length > 0
            visible: (page.win !== null && page.win.appsLoaded) && list.count === 0
            icon.name: anything ? "edit-find" : "application-x-executable"
            text: anything ? qsTr("No apps match your filters") : qsTr("No AppImages found")
            explanation: anything ? "" : qsTr("SAM looks in %1. Add more folders (or the Downloads folder) in Settings, or drag an AppImage into this window.")
                .arg(page.win && page.win.config ? page.win.config.general.scan_directories.join(", ") : "")
            helpfulAction: Kirigami.Action {
                text: qsTr("Sandbox a file…")
                icon.name: "list-add"
                onTriggered: applicationWindow().addDialog.open()
            }
        }
    }
}
