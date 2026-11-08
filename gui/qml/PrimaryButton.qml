// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

/// The one main action of a view (Launch, Create sandbox): filled with the
/// accent colour, like a "suggested action" button.
QQC2.Button {
    id: control
    leftPadding: Kirigami.Units.largeSpacing * 2
    rightPadding: Kirigami.Units.largeSpacing * 2
    topPadding: Kirigami.Units.largeSpacing
    bottomPadding: Kirigami.Units.largeSpacing

    contentItem: RowLayout {
        spacing: Kirigami.Units.smallSpacing
        Kirigami.Icon {
            source: control.icon.name
            visible: control.icon.name !== ""
            color: Kirigami.Theme.highlightedTextColor
            isMask: true
            implicitWidth: Kirigami.Units.iconSizes.small
            implicitHeight: implicitWidth
        }
        QQC2.Label {
            text: control.text
            color: Kirigami.Theme.highlightedTextColor
            font.weight: Font.DemiBold
        }
    }
    background: Rectangle {
        radius: Kirigami.Units.cornerRadius
        color: !control.enabled ? Kirigami.Theme.disabledTextColor
            : control.down ? Qt.darker(Kirigami.Theme.highlightColor, 1.2)
            : control.hovered ? Qt.lighter(Kirigami.Theme.highlightColor, 1.12)
            : Kirigami.Theme.highlightColor
        border.width: control.visualFocus ? 2 : 0
        border.color: Kirigami.Theme.focusColor
    }
}
