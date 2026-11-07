// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

import SAM.Native

/// Pick a preset for an app. Applying checks compatibility first and asks
/// for confirmation when the preset removes needed or adds risky permissions
/// (whitepaper §2.18).
Kirigami.Dialog {
    id: root
    property string appId: ""
    property var presets: []
    property var done: null

    title: qsTr("Apply a preset")
    preferredWidth: Kirigami.Units.gridUnit * 28
    standardButtons: Kirigami.Dialog.Cancel

    function pick(id, cb) {
        appId = id
        done = cb
        Backend.call(["preset", "list"], function (r) {
            if (r.ok)
                root.presets = r.data
        })
        open()
    }

    function tryApply(name) {
        root.close()
        applicationWindow().applyPreset(name, appId, root.done)
    }

    ListView {
        implicitHeight: Kirigami.Units.gridUnit * 18
        model: root.presets
        clip: true
        delegate: QQC2.ItemDelegate {
            required property var modelData
            width: ListView.view.width
            onClicked: root.tryApply(modelData.name)
            contentItem: RowLayout {
                Kirigami.Icon { source: modelData.builtin ? "bookmarks" : "bookmark-new"; implicitWidth: Kirigami.Units.iconSizes.medium; implicitHeight: implicitWidth }
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 0
                    QQC2.Label { text: modelData.name; font.weight: Font.DemiBold; Layout.fillWidth: true; elide: Text.ElideRight }
                    QQC2.Label { text: modelData.description; opacity: 0.7; Layout.fillWidth: true; wrapMode: Text.Wrap; font.pointSize: Math.max(7, Qt.application.font.pointSize - 1) }
                }
                RiskChip { level: modelData.risk; compact: true }
            }
        }
    }
}
