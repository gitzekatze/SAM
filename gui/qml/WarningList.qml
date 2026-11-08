// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.kirigamiaddons.formcard as FormCard
import "Util.js" as Util

/// Plain-language warnings (whitepaper §2.19.3) as quiet rows inside a
/// card, most severe first: a coloured icon, a title and an explanation.
ColumnLayout {
    id: root
    property var warnings: []
    property bool showInfo: true

    spacing: 0

    readonly property var sorted: {
        const order = { "danger": 0, "warning": 1, "info": 2 }
        return (warnings || []).filter(w => root.showInfo || w.severity !== "info")
            .slice().sort((a, b) => order[a.severity] - order[b.severity])
    }

    Repeater {
        model: root.sorted
        delegate: ColumnLayout {
            required property var modelData
            required property int index
            Layout.fillWidth: true
            spacing: 0
            FormCard.FormDelegateSeparator {}
            FormCard.FormTextDelegate {
                text: Util.plain(modelData.title)
                description: Util.plain(modelData.message)
                leading: Kirigami.Icon {
                    source: modelData.severity === "danger" ? "dialog-error" : modelData.severity === "warning" ? "dialog-warning" : "dialog-information"
                    implicitWidth: Kirigami.Units.iconSizes.smallMedium
                    implicitHeight: implicitWidth
                }
                leadingPadding: Kirigami.Units.largeSpacing
            }
        }
    }
}
