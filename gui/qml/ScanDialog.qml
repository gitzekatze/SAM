// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

import Appseal.Native
import "Util.js" as Util

/// Shows AppImages found in the scan directories that are not registered yet.
Kirigami.Dialog {
    id: root
    property var found: []
    readonly property var fresh: found.filter(f => !f.registered)
    property bool quiet: false

    title: qsTr("AppImages found")
    preferredWidth: Kirigami.Units.gridUnit * 30
    standardButtons: Kirigami.Dialog.NoButton

    /// quiet: only open when something new was found (startup auto-scan).
    function scan(isQuiet) {
        quiet = isQuiet
        Backend.call(["scan"], function (r) {
            if (!r.ok) {
                if (!quiet) applicationWindow().reportError(r)
                return
            }
            root.found = r.data.found
            if (root.fresh.length > 0)
                root.open()
            else if (!quiet)
                applicationWindow().notify(r.data.found.length ? qsTr("No new AppImages found") : qsTr("No AppImages found in your scan folders"))
        })
    }

    customFooterActions: [
        Kirigami.Action {
            text: qsTr("Add all")
            icon.name: "list-add"
            enabled: root.fresh.length > 0
            onTriggered: {
                for (const f of root.fresh)
                    applicationWindow().addAppImage(f.path, false)
                root.close()
            }
        },
        Kirigami.Action {
            text: qsTr("Close")
            icon.name: "dialog-close"
            onTriggered: root.close()
        }
    ]

    ListView {
        implicitHeight: Math.min(Kirigami.Units.gridUnit * 18, contentHeight + Kirigami.Units.gridUnit)
        clip: true
        model: root.fresh
        delegate: QQC2.ItemDelegate {
            required property var modelData
            width: ListView.view.width
            contentItem: RowLayout {
                Kirigami.Icon { source: "application-x-executable"; implicitWidth: Kirigami.Units.iconSizes.medium; implicitHeight: implicitWidth }
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 0
                    QQC2.Label { text: modelData.path.split("/").pop(); font.weight: Font.DemiBold; elide: Text.ElideMiddle; Layout.fillWidth: true }
                    QQC2.Label {
                        text: modelData.moved_from ? qsTr("Moved copy of a registered app") : Util.tildify(modelData.path, Backend.homeDir()) + " · " + Backend.humanSize(modelData.size)
                        opacity: 0.7
                        elide: Text.ElideMiddle
                        Layout.fillWidth: true
                        font.pointSize: Math.max(7, Qt.application.font.pointSize - 1)
                    }
                }
                QQC2.Button {
                    text: modelData.moved_from ? qsTr("Update location") : qsTr("Add")
                    onClicked: applicationWindow().addAppImage(modelData.path, false)
                }
            }
        }
    }
}
