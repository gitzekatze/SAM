// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.kirigamiaddons.formcard as FormCard

import "Util.js" as Util

/// Flatseal-style permission editor (whitepaper §2.21.4), shared by the
/// app page and the preset editor. Emits `edited(newPerms)`; the owner
/// persists the change and feeds back `perms` and `evaluation`.
ColumnLayout {
    id: editor

    property var perms: null
    property var evaluation: null
    property bool advanced: QQC2.ApplicationWindow.window ? QQC2.ApplicationWindow.window.advanced : false
    property bool editable: true
    property var catalog: QQC2.ApplicationWindow.window ? QQC2.ApplicationWindow.window.catalog : ({})
    /// Keys of permissions the app likely needs (from the recommendation),
    /// shown with a "Recommended" hint.
    property var recommended: null

    signal edited(var newPerms)

    spacing: 0

    // ------------------------------------------------------------ helpers
    function value(key) {
        return perms ? Util.getPath(perms, key) : undefined
    }
    function info(key) {
        return catalog ? catalog[key] : undefined
    }
    function titleOf(key) {
        const i = info(key)
        return i ? i.title : key
    }
    function isAdvanced(key) {
        const i = info(key)
        return i ? i.advanced : false
    }
    function riskOf(key) {
        const i = info(key)
        return i ? i.risk : "low"
    }
    function riskColor(r) {
        return r === "low" ? Kirigami.Theme.positiveTextColor : r === "medium" ? Kirigami.Theme.neutralTextColor : Kirigami.Theme.negativeTextColor
    }
    function describe(key, override) {
        const i = info(key)
        const text = override || (i ? i.description : "")
        const r = riskOf(key)
        let rec = ""
        if (recommended) {
            const rv = Util.getPath(recommended, key)
            if (rv !== undefined && JSON.stringify(rv) !== JSON.stringify(value(key)) && typeof rv !== "object")
                rec = " <i>" + qsTr("Recommended: %1").arg(String(rv)) + "</i>"
        }
        return "<font color='" + riskColor(r) + "'><b>" + Util.riskLabel(r) + " risk.</b></font> " + text + rec
    }
    function isEnabling(key, v) {
        const cur = value(key)
        if (typeof v === "boolean")
            return v === true && cur !== true
        if (key === "dbus.session.mode")
            return v === "full" && cur !== "full"
        if (key === "dbus.system.mode")
            return v !== "none" && cur === "none"
        if (key === "filesystem.home_access")
            return v === "rw" && cur !== "rw"
        return false
    }
    function needsConfirm(key, v) {
        return isEnabling(key, v) && (riskOf(key) === "dangerous" || key === "dbus.session.mode")
    }
    function apply(key, v) {
        const p = Util.clone(perms)
        Util.setPath(p, key, v)
        edited(p)
    }
    function request(key, v) {
        if (needsConfirm(key, v)) {
            const i = info(key)
            applicationWindow().confirmDialog.ask(
                qsTr("Grant “%1”?").arg(i ? i.title : key),
                (i ? i.description : "") + "\n\n" + qsTr("This is a high-risk permission. Only grant it to applications you trust."),
                function () { editor.apply(key, v) },
                qsTr("Grant"))
            return
        }
        apply(key, v)
    }

    readonly property var accessOptions: [
        { value: "none", text: qsTr("No access") },
        { value: "ro", text: qsTr("Read-only") },
        { value: "rw", text: qsTr("Read & write") }
    ]

    // ------------------------------------------------------------ summary
    FormCard.FormCard {
        Layout.topMargin: Kirigami.Units.largeSpacing
        visible: editor.evaluation !== null
        FormCard.AbstractFormDelegate {
            background: null
            contentItem: ColumnLayout {
                spacing: Kirigami.Units.smallSpacing
                RowLayout {
                    Kirigami.Heading {
                        level: 4
                        text: qsTr("Overall risk")
                        Layout.fillWidth: true
                    }
                    RiskChip {
                        level: editor.evaluation ? editor.evaluation.risk.level : "low"
                        score: editor.evaluation ? editor.evaluation.risk.score : -1
                    }
                }
                QQC2.ProgressBar {
                    Layout.fillWidth: true
                    from: 0
                    to: 100
                    value: editor.evaluation ? editor.evaluation.risk.score : 0
                }
                WarningList {
                    Layout.fillWidth: true
                    warnings: editor.evaluation ? editor.evaluation.warnings : []
                    showInfo: editor.advanced
                }
            }
        }
    }

    // ------------------------------------------------------------ filesystem
    FormCard.FormHeader { title: qsTr("Filesystem") }
    FormCard.FormCard {
        PermSwitch { key: "filesystem.home"; editor: editor }
        PermChoice {
            key: "filesystem.home_access"; editor: editor
            visible: editor.advanced && editor.value("filesystem.home") === true
            options: [{ value: "ro", text: qsTr("Read-only") }, { value: "rw", text: qsTr("Read & write") }]
        }
        FormCard.FormDelegateSeparator {}
        PermChoice { key: "filesystem.documents"; editor: editor; options: editor.accessOptions }
        PermChoice { key: "filesystem.downloads"; editor: editor; options: editor.accessOptions }
        PermChoice { key: "filesystem.pictures"; editor: editor; options: editor.accessOptions }
        PermChoice { key: "filesystem.music"; editor: editor; options: editor.accessOptions }
        PermChoice { key: "filesystem.videos"; editor: editor; options: editor.accessOptions }
        PermChoice { key: "filesystem.desktop"; editor: editor; options: editor.accessOptions }
        FormCard.FormDelegateSeparator { visible: editor.advanced && editor.value("filesystem.home") === true }
        PermSwitch { key: "filesystem.ssh"; editor: editor; visible: editor.advanced && editor.value("filesystem.home") === true }
        PermSwitch { key: "filesystem.gnupg"; editor: editor; visible: editor.advanced && editor.value("filesystem.home") === true }
        PermSwitch { key: "filesystem.hidden_files"; editor: editor; visible: editor.advanced && editor.value("filesystem.home") === true }
        FormCard.FormDelegateSeparator { visible: editor.advanced }
        PathListEditor { key: "filesystem.custom_read"; editor: editor; Layout.fillWidth: true }
        PathListEditor { key: "filesystem.custom_write"; editor: editor; Layout.fillWidth: true }
    }

    // ------------------------------------------------------------ network
    FormCard.FormHeader { title: qsTr("Network") }
    FormCard.FormCard {
        PermChoice {
            key: "network.mode"; editor: editor
            options: editor.advanced
                ? [{ value: "none", text: qsTr("No network") }, { value: "full", text: qsTr("Full network") },
                   { value: "localhost", text: qsTr("Localhost only (experimental)") }, { value: "filtered", text: qsTr("Filtered (experimental)") }]
                : [{ value: "none", text: qsTr("No network") }, { value: "full", text: qsTr("Full network") }]
        }
    }

    // ------------------------------------------------------------ display
    FormCard.FormHeader { title: qsTr("Display") }
    FormCard.FormCard {
        PermSwitch { key: "display.wayland"; editor: editor }
        PermSwitch { key: "display.x11"; editor: editor }
    }

    // ------------------------------------------------------------ devices & audio
    FormCard.FormHeader { title: qsTr("Devices & Audio") }
    FormCard.FormCard {
        PermSwitch { key: "devices.gpu"; editor: editor }
        PermSwitch { key: "audio.enabled"; editor: editor }
        PermSwitch { key: "devices.webcam"; editor: editor }
        PermSwitch { key: "audio.alsa_raw"; editor: editor }
        PermSwitch { key: "devices.input"; editor: editor }
        PermSwitch { key: "devices.usb"; editor: editor }
        PermSwitch { key: "devices.bluetooth"; editor: editor }
    }

    // ------------------------------------------------------------ d-bus
    FormCard.FormHeader { title: qsTr("D-Bus") }
    FormCard.FormCard {
        PermChoice {
            key: "dbus.session.mode"; editor: editor
            options: [{ value: "none", text: qsTr("No access") }, { value: "filtered", text: qsTr("Filtered (portals, notifications, tray)") }, { value: "full", text: qsTr("Full access") }]
        }
        PermChoice {
            key: "dbus.system.mode"; editor: editor
            options: [{ value: "none", text: qsTr("No access") }, { value: "full", text: qsTr("Full access") }]
        }
        PathListEditor {
            key: "dbus.session.allow"; editor: editor; folders: false
            Layout.fillWidth: true
            visible: editor.advanced && editor.value("dbus.session.mode") === "filtered"
            addText: qsTr("Allow a bus name…")
            promptTitle: qsTr("Bus name (wildcards like org.example.* allowed)")
        }
    }

    // ------------------------------------------------------------ sockets & env
    FormCard.FormHeader { title: qsTr("Sockets & Environment"); visible: editor.advanced }
    FormCard.FormCard {
        visible: editor.advanced
        PermSwitch { key: "sockets.ssh_agent"; editor: editor }
        PermSwitch { key: "sockets.cups"; editor: editor }
        PathListEditor {
            key: "environment.passthrough"; editor: editor; folders: false
            Layout.fillWidth: true
            addText: qsTr("Pass a variable…")
            promptTitle: qsTr("Environment variable name")
        }
    }

    // ------------------------------------------------------------ advanced
    FormCard.FormHeader { title: qsTr("Advanced"); visible: editor.advanced }
    FormCard.FormCard {
        visible: editor.advanced
        PermChoice {
            key: "advanced.host_runtime"; editor: editor
            options: [{ value: "minimal", text: qsTr("Minimal (recommended)") }, { value: "full", text: qsTr("All of /usr (compatibility)") }]
        }
        PermSwitch { key: "advanced.persistent_home"; editor: editor }
        PermChoice {
            key: "advanced.landlock"; editor: editor
            options: [{ value: undefined, text: qsTr("Follow global setting") }, { value: true, text: qsTr("Enforce") }, { value: false, text: qsTr("Off") }]
        }
        PermSwitch { key: "advanced.seccomp_strict"; editor: editor }
        PermSwitch { key: "advanced.allow_userns"; editor: editor }
        PermSwitch { key: "advanced.host_themes"; editor: editor }
        PathListEditor {
            key: "advanced.extra_backend_args"; editor: editor; folders: false
            Layout.fillWidth: true
            addText: qsTr("Add argument…")
            promptTitle: qsTr("Raw backend argument")
        }
    }
}
