// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.kirigamiaddons.formcard as FormCard

import SAM.Native

/// Diagnostics screen (whitepaper §2.26).
FormCard.FormCardPage {
    id: page
    title: qsTr("Diagnostics")
    property var report: null
    property var backends: []
    readonly property var win: QQC2.ApplicationWindow.window

    function reload() {
        Backend.call(["doctor"], function (r) {
            if (r.ok) page.report = r.data
            else page.win.reportError(r)
        })
        Backend.call(["backends"], function (r) {
            if (r.ok) page.backends = r.data
        })
    }
    function statusIcon(s) {
        return s === "ok" ? "emblem-ok-symbolic" : s === "info" ? "documentinfo" : s === "warn" ? "data-warning" : "data-error"
    }
    function statusColor(s) {
        return s === "ok" ? Kirigami.Theme.positiveTextColor : s === "info" ? Kirigami.Theme.textColor : s === "warn" ? Kirigami.Theme.neutralTextColor : Kirigami.Theme.negativeTextColor
    }

    Component.onCompleted: reload()

    actions: [
        Kirigami.Action { text: qsTr("Refresh"); icon.name: "view-refresh"; onTriggered: page.reload() },
        Kirigami.Action {
            text: qsTr("Copy bug report")
            icon.name: "edit-copy"
            onTriggered: Backend.call(["report"], function (r) {
                if (r.ok) { Backend.copyToClipboard(r.data.report); page.win.notify(qsTr("Redacted report copied")) }
                else page.win.reportError(r)
            })
        }
    ]

    FormCard.FormHeader { title: qsTr("System") }
    FormCard.FormCard {
        Repeater {
            model: page.report ? page.report.checks : []
            delegate: FormCard.AbstractFormDelegate {
                required property var modelData
                background: null
                contentItem: RowLayout {
                    spacing: Kirigami.Units.largeSpacing
                    Kirigami.Icon {
                        source: page.statusIcon(modelData.status)
                        color: page.statusColor(modelData.status)
                        isMask: true
                        implicitWidth: Kirigami.Units.iconSizes.smallMedium
                        implicitHeight: implicitWidth
                    }
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 0
                        QQC2.Label { text: modelData.label; font.weight: Font.DemiBold }
                        QQC2.Label { text: modelData.detail; wrapMode: Text.Wrap; Layout.fillWidth: true; opacity: 0.8 }
                        QQC2.Label {
                            visible: !!modelData.hint
                            text: "→ " + (modelData.hint || "")
                            wrapMode: Text.Wrap
                            Layout.fillWidth: true
                            color: Kirigami.Theme.linkColor
                        }
                    }
                }
            }
        }
    }

    FormCard.FormHeader { title: qsTr("Sandbox backends") }
    FormCard.FormCard {
        Repeater {
            model: page.backends
            delegate: FormCard.FormTextDelegate {
                required property var modelData
                icon.name: modelData.usable ? "emblem-ok-symbolic" : (modelData.installed ? "data-warning" : "dialog-cancel")
                text: ({ bubblewrap: "Bubblewrap", bubblejail: "Bubblejail", firejail: "Firejail", unsandboxed: qsTr("Unsandboxed") })[modelData.kind]
                    + (modelData.recommended ? "  " + qsTr("(recommended)") : "")
                description: (modelData.usable ? qsTr("Usable") : modelData.installed ? qsTr("Installed, not usable") : qsTr("Not installed"))
                    + (modelData.version ? " · " + modelData.version : "")
                    + (modelData.notes.length ? "\n" + modelData.notes.join("\n") : "")
                    + (modelData.risks.length ? "\n⚠ " + modelData.risks.join("\n⚠ ") : "")
            }
        }
    }

    FormCard.FormHeader { title: qsTr("Maintenance") }
    FormCard.FormCard {
        FormCard.FormButtonDelegate {
            text: qsTr("Check all AppImages for changes")
            icon.name: "view-refresh"
            onClicked: Backend.call(["refresh", "--deep"], function (r) {
                page.win.refreshApps()
                if (r.ok) {
                    const n = r.data.filter(i => i.status === "stale" || i.status === "missing").length
                    page.win.notify(n ? qsTr("%1 app(s) changed or are missing").arg(n) : qsTr("All AppImages are unchanged"))
                }
            })
        }
        FormCard.FormButtonDelegate {
            text: qsTr("Remove unused extractions")
            icon.name: "edit-clear-all"
            onClicked: Backend.call(["cleanup"], function (r) {
                if (r.ok) page.win.notify(qsTr("Removed %1 unused extraction(s)").arg(r.data.length))
            })
        }
        FormCard.FormTextDelegate {
            text: qsTr("Command line")
            description: Backend.cliPath
        }
    }
}
