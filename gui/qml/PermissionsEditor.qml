// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.kirigamiaddons.formcard as FormCard

import "Util.js" as Util

/// Flatseal-style permission editor, shared by the app panel and the preset
/// editor. Every setting is always visible; settings that do not apply right
/// now are greyed out, never hidden. Emits `edited(newPerms)`; the owner
/// persists the change and feeds back `perms` and `evaluation`.
ColumnLayout {
    id: editor

    property var perms: null
    property var evaluation: null
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
        return isEnabling(key, v) && (riskOf(key) === "dangerous" || key === "dbus.session.mode" || key === "integrations.keyring")
    }
    function apply(key, v) {
        const p = Util.clone(perms)
        Util.setPath(p, key, v)
        edited(p)
    }
    function request(key, v) {
        if (key === "dbus.session.allow") {
            const before = value(key) || []
            const added = (v || []).filter(n => before.indexOf(n) < 0 && Util.dangerousBus(n))
            if (added.length) {
                applicationWindow().confirmDialog.ask(qsTr("Allow “%1”?").arg(Util.plain(added.join(", "))),
                    qsTr("This service can act outside the sandbox: start programs, run scripts in the desktop shell or change any setting. An app with access to it can escape the sandbox."),
                    function () { editor.apply(key, v) }, qsTr("Allow anyway"))
                return
            }
        }
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

    readonly property bool fullHome: value("filesystem.home") === true
    readonly property bool localNet: value("network.mode") === "localhost"
    readonly property bool filteredBus: value("dbus.session.mode") === "filtered"

    // ------------------------------------------------------------ risk
    FormCard.FormHeader { title: qsTr("Risk and warnings") }
    FormCard.FormCard {
        FormCard.AbstractFormDelegate {
            background: null
            contentItem: ColumnLayout {
                spacing: Kirigami.Units.smallSpacing
                RowLayout {
                    Layout.fillWidth: true
                    QQC2.Label {
                        text: qsTr("Overall risk of these settings")
                        Layout.fillWidth: true
                    }
                    RiskChip {
                        level: editor.evaluation ? editor.evaluation.risk.level : "low"
                        score: editor.evaluation ? editor.evaluation.risk.score : -1
                    }
                }
                WarningList {
                    Layout.fillWidth: true
                    warnings: editor.evaluation ? editor.evaluation.warnings : []
                    showInfo: true
                }
            }
        }
    }

    // ------------------------------------------------------------ network
    FormCard.FormHeader { title: qsTr("Network") }
    FormCard.FormCard {
        PermChoice {
            key: "network.mode"; editor: editor
            options: [{ value: "none", text: qsTr("No network") }, { value: "localhost", text: qsTr("Local network only (no internet)") },
                      { value: "full", text: qsTr("Full network") }, { value: "filtered", text: qsTr("Filtered (experimental)") }]
        }
        PathListEditor { key: "network.host_ports"; editor: editor; folders: false; available: editor.localNet; Layout.fillWidth: true; placeholder: qsTr("Port on this computer, e.g. 11434 for Ollama") }
        PathListEditor { key: "network.app_ports"; editor: editor; folders: false; available: editor.localNet; Layout.fillWidth: true; placeholder: qsTr("Port of the app, e.g. its web page (empty = automatic)") }
    }

    // ------------------------------------------------------------ display
    FormCard.FormHeader { title: qsTr("Display") }
    FormCard.FormCard {
        PermSwitch { key: "display.wayland"; editor: editor }
        PermSwitch { key: "display.x11"; editor: editor }
    }

    // ------------------------------------------------------------ sound & devices
    FormCard.FormHeader { title: qsTr("Sound & devices") }
    FormCard.FormCard {
        PermSwitch { key: "audio.enabled"; editor: editor }
        PermSwitch { key: "devices.gpu"; editor: editor }
        PermSwitch { key: "devices.webcam"; editor: editor }
        PermSwitch { key: "devices.input"; editor: editor }
        PermSwitch { key: "devices.usb"; editor: editor }
        PermSwitch { key: "devices.bluetooth"; editor: editor }
        PermSwitch { key: "audio.alsa_raw"; editor: editor }
    }

    // ------------------------------------------------------------ filesystem
    FormCard.FormHeader { title: qsTr("Files") }
    FormCard.FormCard {
        PermChoice { key: "filesystem.documents"; editor: editor; options: editor.accessOptions }
        PermChoice { key: "filesystem.downloads"; editor: editor; options: editor.accessOptions }
        PermChoice { key: "filesystem.pictures"; editor: editor; options: editor.accessOptions }
        PermChoice { key: "filesystem.music"; editor: editor; options: editor.accessOptions }
        PermChoice { key: "filesystem.videos"; editor: editor; options: editor.accessOptions }
        PermChoice { key: "filesystem.desktop"; editor: editor; options: editor.accessOptions }
        PermChoice { key: "filesystem.opened_files"; editor: editor; options: [{ value: "ro", text: qsTr("Read-only") }, { value: "rw", text: qsTr("Read & write") }] }
        FormCard.FormDelegateSeparator {}
        PathListEditor { key: "filesystem.custom_read"; editor: editor; Layout.fillWidth: true }
        PathListEditor { key: "filesystem.custom_write"; editor: editor; Layout.fillWidth: true }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "filesystem.home"; editor: editor }
        PermChoice {
            key: "filesystem.home_access"; editor: editor; available: editor.fullHome
            options: [{ value: "ro", text: qsTr("Read-only") }, { value: "rw", text: qsTr("Read & write") }]
        }
        PermSwitch { key: "filesystem.ssh"; editor: editor; available: editor.fullHome }
        PermSwitch { key: "filesystem.gnupg"; editor: editor; available: editor.fullHome }
        PermSwitch { key: "filesystem.hidden_files"; editor: editor; available: editor.fullHome }
    }

    // ------------------------------------------------------------ desktop integration
    FormCard.FormHeader { title: qsTr("Desktop integration") }
    FormCard.FormCard {
        PermSwitch { key: "integrations.file_manager"; editor: editor; available: editor.filteredBus }
        PermSwitch { key: "integrations.media_controls"; editor: editor; available: editor.filteredBus }
        PermSwitch { key: "integrations.screen_sharing"; editor: editor; available: editor.filteredBus }
        PermSwitch { key: "integrations.keyring"; editor: editor; available: editor.filteredBus }
    }

    // ------------------------------------------------------------ d-bus
    FormCard.FormHeader { title: qsTr("D-Bus") }
    FormCard.FormCard {
        PermChoice {
            key: "dbus.session.mode"; editor: editor
            options: [{ value: "none", text: qsTr("No access") }, { value: "filtered", text: qsTr("Filtered (portals, notifications, tray)") }, { value: "full", text: qsTr("Full access") }]
        }
        PathListEditor { key: "dbus.session.allow"; editor: editor; folders: false; available: editor.filteredBus; Layout.fillWidth: true; placeholder: qsTr("Bus name, e.g. org.example.Service") }
        PermChoice {
            key: "dbus.system.mode"; editor: editor
            options: [{ value: "none", text: qsTr("No access") }, { value: "full", text: qsTr("Full access") }]
        }
    }

    // ------------------------------------------------------------ sockets & environment
    FormCard.FormHeader { title: qsTr("Sockets & environment") }
    FormCard.FormCard {
        PermSwitch { key: "sockets.ssh_agent"; editor: editor }
        PermSwitch { key: "sockets.cups"; editor: editor }
        PathListEditor { key: "environment.passthrough"; editor: editor; folders: false; Layout.fillWidth: true; placeholder: qsTr("Variable name, e.g. LANG") }
    }

    // ------------------------------------------------------------ advanced
    FormCard.FormHeader { title: qsTr("Advanced") }
    FormCard.FormCard {
        PermChoice {
            key: "advanced.host_runtime"; editor: editor
            options: [{ value: "minimal", text: qsTr("Minimal (recommended)") }, { value: "full", text: qsTr("All of /usr (compatibility)") }]
        }
        PermSwitch { key: "advanced.persistent_home"; editor: editor }
        PermSwitch { key: "advanced.writable_appdir"; editor: editor }
        PermSwitch { key: "advanced.host_themes"; editor: editor }
        PermSwitch { key: "advanced.allow_userns"; editor: editor }
        PermChoice {
            key: "advanced.landlock"; editor: editor
            options: [{ value: undefined, text: qsTr("Follow global setting") }, { value: true, text: qsTr("Enforce") }, { value: false, text: qsTr("Off") }]
        }
        PermSwitch { key: "advanced.seccomp_baseline"; editor: editor }
        PermSwitch { key: "advanced.seccomp_strict"; editor: editor }
        PathListEditor { key: "advanced.extra_backend_args"; editor: editor; folders: false; Layout.fillWidth: true; placeholder: qsTr("Raw backend argument") }
    }
}
