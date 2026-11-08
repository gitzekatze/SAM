// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs as Dialogs
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.kirigamiaddons.formcard as FormCard

import SAM.Native
import "Util.js" as Util

/// Settings (whitepaper §2.21.6).
FormCard.FormCardPage {
    id: page
    title: qsTr("Settings")
    readonly property var win: QQC2.ApplicationWindow.window
    // Loaded here rather than borrowed from the window, so bindings work
    // even before the page is attached to it.
    property var cfg: null

    function load() {
        Backend.call(["config", "show"], function (r) {
            if (r.ok)
                page.cfg = r.data
        })
    }
    function set(key, value) {
        Backend.call(["config", "set", key, value], function (r) {
            if (!r.ok)
                applicationWindow().reportError(r)
            load()
            // Keep the window (theme) in sync.
            applicationWindow().loadConfig()
            // Scan folders changed: rebuild the overview.
            if (key.indexOf("general.scan") === 0)
                applicationWindow().refreshApps()
        })
    }

    Component.onCompleted: load()

    // A switch bound to a config key that survives the binding break on toggle.
    component ConfigSwitch: FormCard.FormSwitchDelegate {
        id: sw
        required property string key
        property var cfg: null
        property var owner: null
        property string confirmText: ""
        checked: cfg ? Util.getPath(cfg, key) === true : false
        onToggled: {
            const v = checked
            checked = Qt.binding(() => cfg ? Util.getPath(cfg, sw.key) === true : false)
            if (v && confirmText)
                owner.win.confirmDialog.ask(text, confirmText, () => owner.set(sw.key, "true"), qsTr("Enable"))
            else
                owner.set(sw.key, v ? "true" : "false")
        }
    }
    component ConfigChoice: FormCard.FormComboBoxDelegate {
        id: cc
        required property string key
        property var cfg: null
        property var owner: null
        required property var options
        model: options
        textRole: "text"
        valueRole: "value"
        // Bind after the model is set: the inner ComboBox resets its index on model changes.
        Component.onCompleted: currentIndex = Qt.binding(() => Math.max(0, cc.options.findIndex(o => cfg && o.value === Util.getPath(cfg, cc.key))))
        onActivated: index => {
            const v = options[index].value
            currentIndex = Qt.binding(() => Math.max(0, cc.options.findIndex(o => cfg && o.value === Util.getPath(cfg, cc.key))))
            owner.set(cc.key, v)
        }
    }
    component ConfigNumber: FormCard.FormSpinBoxDelegate {
        id: cn
        required property string key
        property var cfg: null
        property var owner: null
        property int scale: 1
        value: cfg ? Util.getPath(cfg, key) / scale : 0
        onValueChanged: if (cfg && value * scale !== Util.getPath(cfg, key)) debounce.restart()
        Timer {
            id: debounce
            interval: 600
            onTriggered: owner.set(cn.key, String(cn.value * cn.scale))
        }
    }

    FormCard.FormHeader { title: qsTr("Appearance") }
    FormCard.FormCard {
        ConfigChoice { cfg: page.cfg; owner: page;
            key: "general.theme"
            text: qsTr("Theme")
            options: Themes.themes.map(t => ({ value: t, text: Themes.label(t) }))
        }
    }

    FormCard.FormHeader { title: qsTr("Menu entries") }
    FormCard.FormCard {
        ConfigSwitch { cfg: page.cfg; owner: page; key: "general.desktop_integration"; text: qsTr("Create menu entries"); description: qsTr("Sandboxed apps appear in your application menu and always start through SAM. AppImage locations are managed in the left column.") }
    }

    FormCard.FormHeader { title: qsTr("Repair") }
    FormCard.FormCard {
        ConfigChoice { cfg: page.cfg; owner: page;
            key: "compatibility.behavior"
            text: qsTr("Compatibility mode")
            options: [{ value: "ask", text: qsTr("Offer in repair options") }, { value: "never", text: qsTr("Never offer") }]
        }
    }

    FormCard.FormHeader { title: qsTr("Warnings") }
    FormCard.FormCard {
        ConfigSwitch { cfg: page.cfg; owner: page; key: "security.warn_x11"; text: qsTr("Warn about X11 access") }
        ConfigSwitch { cfg: page.cfg; owner: page; key: "security.warn_full_home"; text: qsTr("Warn about full home access") }
    }

    FormCard.FormHeader { title: qsTr("Kernel security features") }
    FormCard.FormCard {
        ConfigSwitch { cfg: page.cfg; owner: page;
            key: "security.experimental_landlock"
            text: qsTr("Landlock write protection")
            description: qsTr("Kernel-enforced write restrictions inside the sandbox as an extra layer of defense. Also blocks connections to abstract sockets outside the sandbox (such as XWayland's). Automatically skipped on kernels without Landlock.")
        }
        ConfigSwitch { cfg: page.cfg; owner: page;
            key: "security.baseline_seccomp"
            text: qsTr("Baseline syscall filter")
            description: qsTr("Blocks kernel interfaces no desktop app needs (modules, BPF, perf, keyrings, terminal injection), like Flatpak does. Individual apps can turn it off in their repair steps.")
        }
        ConfigSwitch { cfg: page.cfg; owner: page;
            key: "security.portal_identity"
            text: qsTr("Portal identity for sandboxed apps")
            description: qsTr("Desktop portals treat SAM apps as sandboxed: files picked in a file dialog are handed over safely, and portals apply their own per-app prompts. Some apps may ask once which application to open links with.")
        }
        ConfigSwitch { cfg: page.cfg; owner: page;
            key: "security.experimental_seccomp"
            text: qsTr("Allow strict seccomp filters (experimental)")
            description: qsTr("Lets apps use the strict syscall filter from their Advanced permissions. Can break apps.")
        }
        FormCard.FormSwitchDelegate {
            text: qsTr("eBPF network filtering (experimental)")
            description: qsTr("Not available in this release.")
            enabled: false
        }
    }

    FormCard.FormHeader { title: qsTr("Dependency detection") }
    FormCard.FormCard {
        ConfigSwitch { cfg: page.cfg; owner: page; key: "dependencies.static_analysis"; text: qsTr("Analyze AppImages when creating a sandbox"); description: qsTr("Inspects the bundled programs and libraries without running them.") }
        ConfigSwitch { cfg: page.cfg; owner: page; key: "dependencies.dynamic_fallback"; text: qsTr("Allow diagnostic runs"); description: qsTr("Run an app once under strace to find missing resources (app → Make it work → Diagnose missing resources).") }
        ConfigSwitch { cfg: page.cfg; owner: page; key: "dependencies.automatic_low_risk_fixes"; text: qsTr("Apply low-risk fixes automatically"); description: qsTr("Read-only system data such as fonts or themes found during a diagnostic run is granted without asking.") }
    }

    FormCard.FormHeader { title: qsTr("Extraction") }
    FormCard.FormCard {
        FormCard.FormTextDelegate {
            text: qsTr("Location")
            description: page.cfg && page.cfg.extraction.location ? page.cfg.extraction.location : qsTr("Default (~/.local/share/sam/extracted)")
        }
        ConfigSwitch { cfg: page.cfg; owner: page; key: "extraction.cleanup_stale"; text: qsTr("Clean up stale extractions") }
        ConfigSwitch { cfg: page.cfg; owner: page;
            key: "extraction.allow_fallback"
            text: qsTr("Offer the AppImage's own extractor as fallback")
            description: qsTr("Only used after asking you, and only inside a restricted sandbox.")
        }
        ConfigNumber { cfg: page.cfg; owner: page; key: "extraction.max_size_mb"; label: qsTr("Maximum extracted size (MiB)"); from: 64; to: 1048576; stepSize: 256 }
        ConfigNumber { cfg: page.cfg; owner: page; key: "extraction.max_files"; label: qsTr("Maximum number of files"); from: 1000; to: 10000000; stepSize: 10000 }
        ConfigNumber { cfg: page.cfg; owner: page; key: "extraction.max_seconds"; label: qsTr("Maximum extraction time (s)"); from: 10; to: 7200; stepSize: 30 }
    }

    FormCard.FormHeader { title: qsTr("Diagnostics") }
    FormCard.FormCard {
        ConfigSwitch { cfg: page.cfg; owner: page; key: "diagnostics.verbose_logging"; text: qsTr("Verbose logging") }
        ConfigNumber { cfg: page.cfg; owner: page; key: "diagnostics.keep_logs"; label: qsTr("Launch logs to keep per app"); from: 1; to: 500 }
    }

}
