// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

import Appseal.Native
import "Util.js" as Util

/// Dashboard (whitepaper §2.21.2): app list with search, filters and badges.
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
        return list
    }
    readonly property var attention: page.allApps.filter(a => a.badge !== "ready")

    actions: [
        Kirigami.Action {
            text: qsTr("Add AppImage")
            icon.name: "list-add"
            onTriggered: applicationWindow().addDialog.open()
        },
        Kirigami.Action {
            text: qsTr("Scan")
            icon.name: "edit-find"
            onTriggered: applicationWindow().scanner.scan(false)
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
        visible: page.allApps.length > 0
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
        model: page.filtered
        spacing: Kirigami.Units.smallSpacing
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

        delegate: QQC2.ItemDelegate {
            id: card
            required property var modelData
            width: list.width - list.leftMargin - list.rightMargin
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

        Kirigami.PlaceholderMessage {
            anchors.centerIn: parent
            width: parent.width - Kirigami.Units.gridUnit * 4
            visible: (page.win !== null && page.win.appsLoaded) && list.count === 0
            icon.name: page.allApps.length ? "edit-find" : "application-x-executable"
            text: page.allApps.length ? qsTr("No apps match your filters") : qsTr("No AppImages yet")
            explanation: page.allApps.length ? "" : qsTr("Drag an AppImage into this window, add one from disk, or scan your folders. Appseal unpacks it without running it and recommends safe permissions.")
            helpfulAction: Kirigami.Action {
                text: qsTr("Add AppImage…")
                icon.name: "list-add"
                onTriggered: applicationWindow().addDialog.open()
            }
        }
    }
}
