// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

/// A small tinted label ("Sandboxed", "High risk"): the tone colours the
/// text and a faint background, so several pills stay calm next to each other.
Rectangle {
    id: root
    property string text: ""
    property string iconName: ""
    /// Accent colour; defaults to the normal text colour (neutral pill).
    property color tone: Kirigami.Theme.textColor
    /// Solid background for the strongest emphasis (dangerous settings).
    property bool solid: false
    /// Collapses the pill (zero width, transparent) without hiding it, so
    /// layout proxies such as FormCard's trailing slot keep tracking it.
    property bool shown: true

    implicitHeight: Math.round(Kirigami.Units.gridUnit * 1.3)
    implicitWidth: shown ? row.implicitWidth + Kirigami.Units.largeSpacing * 1.5 : 0
    opacity: shown ? 1 : 0
    radius: height / 2
    color: solid ? tone : Qt.rgba(tone.r, tone.g, tone.b, 0.14)

    RowLayout {
        id: row
        anchors.centerIn: parent
        spacing: Kirigami.Units.smallSpacing
        Kirigami.Icon {
            visible: root.iconName !== ""
            source: root.iconName
            color: root.solid ? Kirigami.Theme.highlightedTextColor : root.tone
            isMask: true
            implicitWidth: Kirigami.Units.iconSizes.small
            implicitHeight: implicitWidth
        }
        QQC2.Label {
            text: root.text
            textFormat: Text.PlainText
            color: root.solid ? Kirigami.Theme.highlightedTextColor : root.tone
            font.pointSize: Math.max(7, Qt.application.font.pointSize - 1)
            font.weight: Font.DemiBold
        }
    }
}
