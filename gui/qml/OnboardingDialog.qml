// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

import SAM.Native

/// Short, skippable first-run explanation (whitepaper §2.20.1).
Kirigami.Dialog {
    id: root
    property int step: 0

    readonly property var steps: [
        { icon: "qrc:/qt/qml/SAM/icons/sam.svg", title: qsTr("Welcome to SAM"),
          text: qsTr("SAM lists the AppImages on your computer and lets you put each one in a sandbox, then decide what it may access, like Flatseal does for Flatpak. Only sandboxed apps get a SAM menu entry.") },
        { icon: "security-high", title: qsTr("What sandboxing means"),
          text: qsTr("A sandboxed app only sees what you allow: it gets its own private settings folder instead of your home directory, and cannot reach your other files, the network or devices unless you grant them.") },
        { icon: "preferences-system-privacy", title: qsTr("Permissions"),
          text: qsTr("When you create a sandbox, SAM looks at it without running it and suggests safe permissions: a browser gets the network and Downloads, an image editor gets Pictures. Every toggle explains what it allows and how risky it is.") },
        { icon: "tools-wizard", title: qsTr("Compatibility mode"),
          text: qsTr("Some AppImages need more access to work. If an app breaks, SAM's repair options can grant broader access, always with a clear warning about what you give up.") },
        { icon: "video-display", title: qsTr("Wayland is safer than X11"),
          text: qsTr("On X11, any app can watch your keyboard and other windows. Wayland isolates apps from each other. SAM warns you whenever an app gets X11 access.") },
        { icon: "dialog-warning", title: qsTr("No perfect security"),
          text: qsTr("SAM makes AppImages much safer, but it cannot protect against kernel exploits or apps you grant broad access. Only run software you have reason to trust.") }
    ]

    title: ""
    preferredWidth: Kirigami.Units.gridUnit * 30
    standardButtons: Kirigami.Dialog.NoButton
    closePolicy: QQC2.Popup.CloseOnEscape

    function finish() {
        Backend.call(["onboarding", "done"], function () {})
        close()
        step = 0
    }

    onRejected: finish()

    customFooterActions: [
        Kirigami.Action {
            text: qsTr("Skip")
            visible: root.step < root.steps.length - 1
            onTriggered: root.finish()
        },
        Kirigami.Action {
            text: qsTr("Back")
            icon.name: "go-previous"
            enabled: root.step > 0
            onTriggered: root.step--
        },
        Kirigami.Action {
            text: root.step < root.steps.length - 1 ? qsTr("Next") : qsTr("Get started")
            icon.name: root.step < root.steps.length - 1 ? "go-next" : "dialog-ok-apply"
            onTriggered: root.step < root.steps.length - 1 ? root.step++ : root.finish()
        }
    ]

    ColumnLayout {
        spacing: Kirigami.Units.largeSpacing
        Layout.preferredWidth: Kirigami.Units.gridUnit * 26
        Layout.margins: Kirigami.Units.largeSpacing
        Kirigami.Icon {
            source: root.steps[root.step].icon
            Layout.alignment: Qt.AlignHCenter
            implicitWidth: Kirigami.Units.iconSizes.enormous
            implicitHeight: implicitWidth
        }
        Kirigami.Heading {
            text: root.steps[root.step].title
            level: 2
            Layout.fillWidth: true
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.Wrap
        }
        QQC2.Label {
            text: root.steps[root.step].text
            Layout.fillWidth: true
            Layout.preferredWidth: Kirigami.Units.gridUnit * 26
            Layout.minimumHeight: Kirigami.Units.gridUnit * 5
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
        }
        Row {
            Layout.alignment: Qt.AlignHCenter
            spacing: Kirigami.Units.smallSpacing
            Repeater {
                model: root.steps.length
                delegate: Rectangle {
                    required property int index
                    width: Kirigami.Units.smallSpacing * 2
                    height: width
                    radius: width / 2
                    color: index === root.step ? Kirigami.Theme.highlightColor : Kirigami.Theme.disabledTextColor
                }
            }
        }
    }
}
