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
    /// Nothing can be changed until the settings are loaded.
    property bool editable: perms !== null && perms !== undefined
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
    /// Grey description under a setting, plus SAM's recommendation when the
    /// current value differs from it.
    function describe(key, override) {
        const i = info(key)
        const text = override || (i ? i.description : "")
        if (recommended) {
            const rv = Util.getPath(recommended, key)
            if (rv !== undefined && JSON.stringify(rv) !== JSON.stringify(value(key)) && typeof rv !== "object")
                return "<html>" + Util.esc(text) + "<br/><i>" + qsTr("SAM recommends: %1").arg(Util.esc(valueLabel(rv))) + "</i></html>"
        }
        return text
    }
    function valueLabel(v) {
        if (v === true) return qsTr("on")
        if (v === false) return qsTr("off")
        const names = { none: qsTr("none"), ro: qsTr("read-only"), rw: qsTr("read & write"), full: qsTr("full"),
                        localhost: qsTr("local network only"), filtered: qsTr("filtered"), minimal: qsTr("minimal") }
        return names[v] || String(v)
    }
    /// Risk level shown as a pill next to a setting: only while the setting
    /// is in use and its risk is high or dangerous, so the list stays calm.
    function activeRisk(key) {
        const v = value(key)
        // Choices whose risk rating only applies to one option.
        const risky = { "network.mode": ["full"], "dbus.session.mode": ["full"], "dbus.system.mode": ["full"], "filesystem.home_access": ["rw"] }
        let on
        if (risky[key])
            on = risky[key].indexOf(v) >= 0
        else
            on = v === true || (typeof v === "string" && v !== "none" && v !== "minimal" && v !== "ro") || (Array.isArray(v) && v.length > 0)
        if (key === "filesystem.home_access" || key === "filesystem.ssh" || key === "filesystem.gnupg" || key === "filesystem.hidden_files")
            on = on && fullHome
        const r = riskOf(key)
        return on && (r === "high" || r === "dangerous") ? r : ""
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
        { value: "none", text: qsTr("No access"), description: qsTr("Hidden from the app.") },
        { value: "ro", text: qsTr("Read-only"), description: qsTr("The app can open files here but not change or delete them.") },
        { value: "rw", text: qsTr("Read & write"), description: qsTr("The app can open, change and delete files here.") }
    ]

    readonly property bool fullHome: value("filesystem.home") === true
    readonly property bool localNet: value("network.mode") === "localhost"
    readonly property bool filteredBus: value("dbus.session.mode") === "filtered"
    readonly property bool anyBus: value("dbus.session.mode") !== "none"
    /// "All input devices" already includes the game controllers.
    readonly property bool allInput: value("devices.input") === true

    // ------------------------------------------------------------ risk
    FormCard.FormHeader { title: qsTr("Overview") }
    FormCard.FormCard {
        FormCard.FormTextDelegate {
            text: qsTr("Risk of these settings")
            description: {
                const n = editor.evaluation ? editor.evaluation.warnings.filter(w => w.severity !== "info").length : 0
                return n === 0 ? qsTr("Nothing to watch out for.") : n === 1 ? qsTr("One thing to watch out for, listed below.") : qsTr("%1 things to watch out for, listed below.").arg(n)
            }
            trailing: RiskChip {
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

    // ------------------------------------------------------------ network
    FormCard.FormHeader { title: qsTr("Network") }
    FormCard.FormCard {
        PermChoice {
            key: "network.mode"; editor: editor
            options: [{ value: "none", text: qsTr("No network"), description: qsTr("No connection at all, not even to this computer.") },
                      { value: "localhost", text: qsTr("Local network only (no internet)"), description: qsTr("No internet. The app can reach the services on this computer you list below, and its own web page opens in your browser.") },
                      { value: "full", text: qsTr("Full network"), description: qsTr("The app uses your internet connection like any other program.") },
                      { value: "filtered", text: qsTr("Filtered (experimental)"), description: qsTr("Not enforced yet: the app gets no network.") }]
        }
        FormCard.FormDelegateSeparator {}
        PathListEditor { key: "network.host_ports"; editor: editor; folders: false; available: editor.localNet; Layout.fillWidth: true; placeholder: qsTr("Port on this computer, e.g. 11434 for Ollama") }
        FormCard.FormDelegateSeparator {}
        PathListEditor { key: "network.app_ports"; editor: editor; folders: false; available: editor.localNet; Layout.fillWidth: true; placeholder: qsTr("Port of the app, e.g. its web page (empty = automatic)") }
    }

    // ------------------------------------------------------------ display
    FormCard.FormHeader { title: qsTr("Display") }
    FormCard.FormCard {
        PermSwitch { key: "display.wayland"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "display.x11"; editor: editor }
    }

    // ------------------------------------------------------------ sound & devices
    FormCard.FormHeader { title: qsTr("Sound & devices") }
    FormCard.FormCard {
        PermSwitch { key: "audio.enabled"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "devices.gpu"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "devices.webcam"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "devices.gamepads"; editor: editor; available: !editor.allInput }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "devices.input"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "devices.usb"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "devices.bluetooth"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "audio.alsa_raw"; editor: editor }
    }

    // ------------------------------------------------------------ filesystem
    FormCard.FormHeader { title: qsTr("Files") }
    FormCard.FormCard {
        PermChoiceInline { key: "filesystem.documents"; editor: editor; options: editor.accessOptions }
        FormCard.FormDelegateSeparator {}
        PermChoiceInline { key: "filesystem.downloads"; editor: editor; options: editor.accessOptions }
        FormCard.FormDelegateSeparator {}
        PermChoiceInline { key: "filesystem.pictures"; editor: editor; options: editor.accessOptions }
        FormCard.FormDelegateSeparator {}
        PermChoiceInline { key: "filesystem.music"; editor: editor; options: editor.accessOptions }
        FormCard.FormDelegateSeparator {}
        PermChoiceInline { key: "filesystem.videos"; editor: editor; options: editor.accessOptions }
        FormCard.FormDelegateSeparator {}
        PermChoiceInline { key: "filesystem.desktop"; editor: editor; options: editor.accessOptions }
        FormCard.FormDelegateSeparator {}
        PermChoiceInline { key: "filesystem.opened_files"; editor: editor; options: [{ value: "ro", text: qsTr("Read-only"), description: qsTr("The app can view the files but not save changes.") }, { value: "rw", text: qsTr("Read & write"), description: qsTr("The app can view and save the files.") }] }
        FormCard.FormDelegateSeparator {}
        PathListEditor { key: "filesystem.custom_read"; editor: editor; Layout.fillWidth: true }
        FormCard.FormDelegateSeparator {}
        PathListEditor { key: "filesystem.custom_write"; editor: editor; Layout.fillWidth: true }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "filesystem.home"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PermChoiceInline {
            key: "filesystem.home_access"; editor: editor; available: editor.fullHome
            options: [{ value: "ro", text: qsTr("Read-only") }, { value: "rw", text: qsTr("Read & write") }]
        }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "filesystem.ssh"; editor: editor; available: editor.fullHome }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "filesystem.gnupg"; editor: editor; available: editor.fullHome }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "filesystem.hidden_files"; editor: editor; available: editor.fullHome }
    }

    // ------------------------------------------------------------ desktop integration
    FormCard.FormHeader { title: qsTr("Desktop integration") }
    FormCard.FormCard {
        PermSwitch { key: "integrations.file_manager"; editor: editor; available: editor.filteredBus }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "integrations.media_controls"; editor: editor; available: editor.filteredBus }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "integrations.screen_sharing"; editor: editor; available: editor.filteredBus }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "integrations.keyring"; editor: editor; available: editor.filteredBus }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "integrations.input_method"; editor: editor; available: editor.anyBus }
    }

    // ------------------------------------------------------------ d-bus
    FormCard.FormHeader { title: qsTr("D-Bus") }
    FormCard.FormCard {
        PermChoice {
            key: "dbus.session.mode"; editor: editor
            options: [{ value: "none", text: qsTr("No access"), description: qsTr("No desktop services: no file dialogs, notifications or tray icon.") },
                      { value: "filtered", text: qsTr("Filtered (portals, notifications, tray)"), description: qsTr("File dialogs, notifications, the tray and the services you allow below. Everything else is blocked.") },
                      { value: "full", text: qsTr("Full access"), description: qsTr("Every desktop service, including ones that can act outside the sandbox.") }]
        }
        FormCard.FormDelegateSeparator {}
        PathListEditor { key: "dbus.session.allow"; editor: editor; folders: false; available: editor.filteredBus; Layout.fillWidth: true; placeholder: qsTr("Bus name, e.g. org.example.Service") }
        FormCard.FormDelegateSeparator {}
        PermChoiceInline {
            key: "dbus.system.mode"; editor: editor
            options: [{ value: "none", text: qsTr("No access") }, { value: "full", text: qsTr("Full access") }]
        }
    }

    // ------------------------------------------------------------ sockets & environment
    FormCard.FormHeader { title: qsTr("Sockets & environment") }
    FormCard.FormCard {
        PermSwitch { key: "sockets.ssh_agent"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "sockets.cups"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PathListEditor { key: "environment.passthrough"; editor: editor; folders: false; Layout.fillWidth: true; placeholder: qsTr("Variable name, e.g. LANG") }
    }

    // ------------------------------------------------------------ advanced
    FormCard.FormHeader { title: qsTr("Advanced") }
    FormCard.FormCard {
        PermChoiceInline {
            key: "advanced.host_runtime"; editor: editor
            options: [{ value: "minimal", text: qsTr("Minimal"), description: qsTr("System libraries plus a short list of shared data (fonts, icons, themes).") },
                      { value: "full", text: qsTr("All of /usr"), description: qsTr("Everything installed on the system, read-only. For apps that look for programs or data elsewhere.") }]
        }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "advanced.persistent_home"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "advanced.writable_appdir"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "advanced.host_themes"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "advanced.allow_userns"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PermChoiceInline {
            key: "advanced.landlock"; editor: editor
            options: [{ value: undefined, text: qsTr("Follow global setting") }, { value: true, text: qsTr("Enforce") }, { value: false, text: qsTr("Off") }]
        }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "advanced.seccomp_baseline"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PermSwitch { key: "advanced.seccomp_strict"; editor: editor }
        FormCard.FormDelegateSeparator {}
        PathListEditor { key: "advanced.extra_backend_args"; editor: editor; folders: false; Layout.fillWidth: true; placeholder: qsTr("Raw bwrap argument, e.g. --setenv FOO 1") }
    }
}
