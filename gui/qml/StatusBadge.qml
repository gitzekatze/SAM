// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import org.kde.kirigami as Kirigami

import "Util.js" as Util

/// App status badge (whitepaper §2.20.4).
Rectangle {
    id: root
    property string badge: "ready"

    readonly property color tone: {
        switch (badge) {
        case "ready": return Kirigami.Theme.positiveTextColor
        case "needs-review": return Kirigami.Theme.highlightColor
        case "compatibility-risk":
        case "stale": return Kirigami.Theme.neutralTextColor
        default: return Kirigami.Theme.negativeTextColor
        }
    }
    readonly property string iconName: {
        switch (badge) {
        case "ready": return "emblem-ok-symbolic"
        case "needs-review": return "view-visible-symbolic"
        case "compatibility-risk": return "data-warning-symbolic"
        case "stale": return "view-refresh-symbolic"
        case "missing": return "edit-find-symbolic"
        default: return "data-error-symbolic"
        }
    }

    implicitHeight: row.implicitHeight + Kirigami.Units.smallSpacing
    implicitWidth: row.implicitWidth + Kirigami.Units.largeSpacing
    radius: height / 2
    color: Qt.rgba(tone.r, tone.g, tone.b, 0.16)
    border.color: Qt.rgba(tone.r, tone.g, tone.b, 0.55)
    border.width: 1

    Row {
        id: row
        anchors.centerIn: parent
        spacing: Kirigami.Units.smallSpacing
        Kirigami.Icon {
            source: root.iconName
            width: Kirigami.Units.iconSizes.small
            height: width
            color: root.tone
            isMask: true
            anchors.verticalCenter: parent.verticalCenter
        }
        QQC2.Label {
            text: Util.badgeLabels[root.badge] || root.badge
            color: root.tone
            font.weight: Font.DemiBold
            font.pointSize: Math.max(7, Qt.application.font.pointSize - 1)
            anchors.verticalCenter: parent.verticalCenter
        }
    }
}
