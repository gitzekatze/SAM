// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import "Util.js" as Util

/// Plain-language warnings (whitepaper §2.19.3), most severe first.
ColumnLayout {
    id: root
    property var warnings: []
    property bool showInfo: true

    spacing: Kirigami.Units.smallSpacing

    readonly property var sorted: {
        const order = { "danger": 0, "warning": 1, "info": 2 }
        return (warnings || []).filter(w => root.showInfo || w.severity !== "info")
            .slice().sort((a, b) => order[a.severity] - order[b.severity])
    }

    Repeater {
        model: root.sorted
        delegate: Kirigami.InlineMessage {
            required property var modelData
            Layout.fillWidth: true
            visible: true
            type: modelData.severity === "danger" ? Kirigami.MessageType.Error
                : modelData.severity === "warning" ? Kirigami.MessageType.Warning
                : Kirigami.MessageType.Information
            text: "<b>" + Util.esc(modelData.title) + "</b> — " + Util.esc(modelData.message)
        }
    }
}
