// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import org.kde.kirigami as Kirigami

import "Util.js" as Util

/// Risk level indicator (whitepaper §2.19.2).
Rectangle {
    id: root
    property string level: "low"
    property int score: -1
    property bool compact: false

    readonly property color tone: level === "low" ? Kirigami.Theme.positiveTextColor
        : level === "medium" ? Kirigami.Theme.neutralTextColor
        : Kirigami.Theme.negativeTextColor

    implicitHeight: label.implicitHeight + Kirigami.Units.smallSpacing
    implicitWidth: label.implicitWidth + Kirigami.Units.largeSpacing
    radius: Kirigami.Units.cornerRadius
    color: level === "dangerous" ? tone : Qt.rgba(tone.r, tone.g, tone.b, 0.16)

    QQC2.Label {
        id: label
        anchors.centerIn: parent
        text: (root.compact ? "" : qsTr("Risk: ")) + Util.riskLabel(root.level) + (root.score >= 0 && !root.compact ? "  " + root.score + "/100" : "")
        color: root.level === "dangerous" ? Kirigami.Theme.backgroundColor : root.tone
        font.weight: Font.DemiBold
        font.pointSize: Math.max(7, Qt.application.font.pointSize - 1)
    }
}
