// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import org.kde.kirigami as Kirigami

import "Util.js" as Util

/// Risk level as a pill (whitepaper §2.19.2): green, amber or red.
Pill {
    id: root
    property string level: "low"
    property int score: -1
    property bool compact: false

    tone: level === "low" ? Kirigami.Theme.positiveTextColor
        : level === "medium" ? Kirigami.Theme.neutralTextColor
        : Kirigami.Theme.negativeTextColor
    solid: level === "dangerous"
    text: qsTr("%1 risk").arg(Util.riskLabel(level)) + (score >= 0 && !compact ? " · " + score : "")
}
