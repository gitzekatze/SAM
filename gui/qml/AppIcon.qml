// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import org.kde.kirigami as Kirigami

import "Util.js" as Util

/// App icon from Appseal's icon cache, with a graceful fallback.
Kirigami.Icon {
    property string path: ""
    source: path ? Util.iconUrl(path) : "application-x-executable"
    fallback: "application-x-executable"
}
