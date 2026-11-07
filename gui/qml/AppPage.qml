// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs as Dialogs
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.kirigamiaddons.formcard as FormCard

import SAM.Native
import "Util.js" as Util

/// App details, permissions editor, repair workflow and logs
/// (whitepaper §2.21.3, §2.21.4, §2.20.6, §2.20.7).
Kirigami.ScrollablePage {
    id: page

    required property string appId
    /// Opened right after "Create sandbox": show the first-run check once.
    property bool firstRun: false
    property var info: null          // { app, entry, warnings, selection, hints, repair_steps, private_home }
    property var evaluation: null
    property string commandText: ""
    property string logText: ""
    property string logKind: "launch"
    property int tab: 0

    readonly property var entry: info ? info.entry : null
    readonly property var summary: info ? info.app : null
    readonly property bool advanced: win ? win.advanced : false
    readonly property var win: QQC2.ApplicationWindow.window

    title: summary ? summary.name : qsTr("Application")

    function reload() {
        Backend.call(["info", appId], function (r) {
            if (!r.ok) {
                win.reportError(r)
                return
            }
            page.info = r.data
            evaluate(r.data.entry.profile.permissions)
            if (page.firstRun && r.data.hints.length) {
                page.firstRun = false
                hintsDialog.open()
            }
            if (page.advanced)
                loadCommand()
        })
    }
    function evaluate(perms) {
        Backend.call(["evaluate", appId], function (r) {
            if (r.ok)
                page.evaluation = r.data
        }, JSON.stringify(perms))
    }
    function loadCommand() {
        Backend.call(["command", appId], function (r) {
            page.commandText = r.ok ? r.data.command : (r.error || "")
        })
    }
    function loadLogs() {
        Backend.call(["logs", appId, "--kind", logKind, "--tail", "400"], function (r) {
            page.logText = r.ok ? r.data.text : (r.error || qsTr("No logs yet."))
        })
    }
    function savePerms(p) {
        Backend.call(["profile", "set", appId], function (r) {
            if (!r.ok)
                win.reportError(r)
            reload()
            win.refreshApps()
        }, JSON.stringify(p))
    }
    function simple(args, done, okText) {
        Backend.call(args, function (r) {
            if (r.ok && okText)
                win.notify(okText)
            if (!r.ok)
                win.reportError(r)
            reload()
            win.refreshApps()
            if (done)
                done(r)
        })
    }
    /// Apply a hint (`hints --apply`) or a repair step / finding (`repair --apply`).
    function applySuggestion(sug, asRepair, thenRun) {
        const run = () => page.simple(asRepair ? ["repair", appId, "--apply", sug.id] : ["hints", appId, "--apply", sug.id], function (r) {
            if (r.ok && thenRun)
                win.launch(appId)
        }, qsTr("Applied: %1").arg(sug.title))
        if (sug.risk === "high" || sug.risk === "dangerous" || sug.action.kind === "compat")
            win.confirmDialog.ask(qsTr("Apply “%1”?").arg(sug.title), sug.explanation, run, qsTr("Apply"))
        else
            run()
    }
    function openPrivateFolder() {
        if (page.info && page.info.private_home)
            Qt.openUrlExternally(Backend.pathToUrl(page.info.private_home))
    }

    function setBackend(choice) {
        const go = confirm => page.simple(["backend", appId, choice].concat(confirm ? ["--confirm"] : []), null, qsTr("Backend set to %1").arg(Util.backendLabels[choice]))
        if (choice === "unsandboxed") {
            win.confirmDialog.ask(qsTr("Run without a sandbox?"),
                qsTr("%1 will run with all of your permissions: every file, the network and all devices. Run unsandboxed only if you trust this application.").arg(page.title),
                () => go(true), qsTr("Run unsandboxed"))
        } else if (choice === "firejail") {
            win.confirmDialog.ask(qsTr("Use Firejail?"),
                qsTr("Firejail is a setuid-root program. Bugs in it have historically allowed privilege escalation. Use it only for compatibility."),
                () => go(true), qsTr("Use Firejail"))
        } else {
            go(false)
        }
    }

    Component.onCompleted: reload()
    onTabChanged: if (tab === 2) loadLogs()

    actions: [
        Kirigami.Action {
            text: qsTr("Run")
            icon.name: "media-playback-start"
            enabled: page.summary !== null && page.summary.badge !== "missing"
            onTriggered: win.launch(page.appId)
        },
        Kirigami.Action {
            text: qsTr("Files this app saved")
            icon.name: "folder-open"
            displayHint: Kirigami.DisplayHint.AlwaysHide
            onTriggered: page.openPrivateFolder()
        },
        Kirigami.Action {
            text: qsTr("Reset to recommended")
            icon.name: "edit-undo"
            displayHint: Kirigami.DisplayHint.AlwaysHide
            onTriggered: page.simple(["profile", "reset", page.appId], null, qsTr("Profile reset"))
        },
        Kirigami.Action {
            text: qsTr("Remove sandbox…")
            icon.name: "edit-delete"
            displayHint: Kirigami.DisplayHint.AlwaysHide
            onTriggered: win.confirmDialog.ask(qsTr("Remove the sandbox for %1?").arg(page.title),
                qsTr("The extracted copy, SAM's menu entry, logs and the app's private settings are deleted. The AppImage file itself is kept, and any menu entry SAM hid is shown again. %1 moves back to “Not sandboxed”.").arg(page.title),
                () => Backend.call(["remove", page.appId], function (r) {
                    if (!r.ok) { win.reportError(r); return }
                    win.notify(qsTr("Removed the sandbox for %1").arg(page.title))
                    win.refreshApps()
                    win.showSection("apps")
                }), qsTr("Remove sandbox"))
        }
    ]

    header: QQC2.TabBar {
        id: tabs
        currentIndex: page.tab
        onCurrentIndexChanged: page.tab = currentIndex
        QQC2.TabButton { text: qsTr("Permissions"); icon.name: "security-medium" }
        QQC2.TabButton { text: qsTr("Details & Repair"); icon.name: "documentinfo" }
        QQC2.TabButton { text: qsTr("Logs"); icon.name: "view-list-text" }
    }

    ColumnLayout {
        spacing: 0

        // ---------------------------------------------------- app header
        RowLayout {
            Layout.fillWidth: true
            Layout.margins: Kirigami.Units.largeSpacing * 2
            Layout.bottomMargin: Kirigami.Units.largeSpacing
            spacing: Kirigami.Units.largeSpacing
            visible: page.summary !== null
            AppIcon {
                path: page.summary ? (page.summary.icon_path || "") : ""
                Layout.preferredWidth: Kirigami.Units.iconSizes.huge
                Layout.preferredHeight: Kirigami.Units.iconSizes.huge
            }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: Kirigami.Units.smallSpacing
                Kirigami.Heading { text: page.title; level: 1; Layout.fillWidth: true; elide: Text.ElideRight }
                QQC2.Label {
                    text: page.entry ? (page.entry.metadata.comment || Util.categoryLabel(page.entry.category)) : ""
                    opacity: 0.75
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                }
                Flow {
                    Layout.fillWidth: true
                    spacing: Kirigami.Units.smallSpacing
                    StatusBadge { badge: page.summary ? page.summary.badge : "ready" }
                    RiskChip {
                        level: page.evaluation ? page.evaluation.risk.level : (page.summary ? page.summary.risk.level : "low")
                        score: page.evaluation ? page.evaluation.risk.score : -1
                    }
                    QQC2.Label {
                        id: backendLabel
                        text: page.info && page.info.selection
                            ? (page.entry && page.entry.profile.backend === "auto" && page.entry.profile.auto_backend
                                ? qsTr("Sandbox: %1 (picked for this app)").arg(Util.backendLabels[page.info.selection.kind])
                                : qsTr("Sandbox: %1").arg(Util.backendLabels[page.info.selection.kind]))
                            : qsTr("No sandbox backend available")
                        opacity: 0.7
                        font.pointSize: Math.max(7, Qt.application.font.pointSize - 1)
                        HoverHandler { id: backendHover }
                        QQC2.ToolTip.visible: backendHover.hovered && page.info !== null && page.info.selection !== null
                        QQC2.ToolTip.text: page.info && page.info.selection ? page.info.selection.reason : ""
                    }
                }
            }
        }

        // What the chosen backend does not enforce for this app.
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            Layout.leftMargin: Kirigami.Units.largeSpacing * 2
            Layout.rightMargin: Kirigami.Units.largeSpacing * 2
            visible: page.info !== null && page.info.selection !== null && (page.info.selection.limitations || []).length > 0
            type: Kirigami.MessageType.Warning
            text: page.info && page.info.selection
                ? qsTr("With %1 some settings are not enforced:\n• %2").arg(Util.backendLabels[page.info.selection.kind]).arg((page.info.selection.limitations || []).join("\n• "))
                : ""
        }

        // Review / unsafe banners.
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            Layout.leftMargin: Kirigami.Units.largeSpacing * 2
            Layout.rightMargin: Kirigami.Units.largeSpacing * 2
            visible: page.summary !== null && page.summary.badge === "needs-review"
            type: Kirigami.MessageType.Information
            text: page.entry && page.entry.pending_changes.length
                ? qsTr("The updated AppImage likely needs: %1. Your customized profile was kept. Review it, then confirm.").arg(page.entry.pending_changes.join(", "))
                : qsTr("SAM picked these permissions from the app's metadata and libraries. Review them, then confirm.")
            actions: [
                Kirigami.Action {
                    text: qsTr("Looks good")
                    icon.name: "dialog-ok-apply"
                    onTriggered: page.simple(["review", page.appId], null, qsTr("Marked as reviewed"))
                }
            ]
        }
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            Layout.margins: Kirigami.Units.largeSpacing * 2
            visible: page.entry !== null && page.entry.detection !== null && page.entry.detection.verdict === "unsafe-to-sandbox"
            type: Kirigami.MessageType.Error
            text: qsTr("This app requires access that cannot be safely sandboxed. Run unsandboxed only if you trust this application.")
        }
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            Layout.margins: Kirigami.Units.largeSpacing * 2
            visible: page.summary !== null && (page.summary.badge === "stale" || page.summary.badge === "broken" || page.summary.badge === "missing")
            type: page.summary && page.summary.badge === "stale" ? Kirigami.MessageType.Warning : Kirigami.MessageType.Error
            text: page.summary === null ? "" : page.summary.badge === "stale" ? qsTr("The AppImage changed since it was extracted.")
                : page.summary.badge === "missing" ? qsTr("The AppImage file is missing. You can still run the extracted copy, point SAM at the new location, or remove the app.")
                : (page.entry && page.entry.last_error ? page.entry.last_error : qsTr("This app cannot start."))
            actions: [
                Kirigami.Action {
                    text: qsTr("Re-extract")
                    icon.name: "view-refresh"
                    visible: page.summary !== null && page.summary.badge !== "missing"
                    onTriggered: win.reextract(page.appId, false, () => page.reload())
                },
                Kirigami.Action {
                    text: qsTr("Locate…")
                    icon.name: "document-open"
                    visible: page.summary !== null && page.summary.badge === "missing"
                    onTriggered: relocateDialog.open()
                },
                Kirigami.Action {
                    text: qsTr("Repair options")
                    icon.name: "tools"
                    onTriggered: page.tab = 1
                }
            ]
        }

        // ---------------------------------------------------- permissions tab
        ColumnLayout {
            visible: page.tab === 0
            Layout.fillWidth: true
            spacing: 0

            PermissionsEditor {
                Layout.fillWidth: true
                perms: page.entry ? page.entry.profile.permissions : null
                recommended: page.entry ? page.entry.recommended : null
                evaluation: page.evaluation
                onEdited: newPerms => {
                    page.evaluate(newPerms)
                    page.savePerms(newPerms)
                }
            }

            FormCard.FormHeader { title: qsTr("Profile") }
            FormCard.FormCard {
                FormCard.FormTextDelegate {
                    text: qsTr("Preset")
                    description: page.entry && page.entry.profile.preset ? page.entry.profile.preset : (page.entry && page.entry.profile.user_modified ? qsTr("Customized") : qsTr("Recommended profile"))
                }
                FormCard.FormButtonDelegate {
                    text: qsTr("Apply a preset…")
                    icon.name: "bookmarks"
                    onClicked: presetPicker.pick(page.appId, () => page.reload())
                }
                FormCard.FormButtonDelegate {
                    text: qsTr("Save as preset…")
                    icon.name: "bookmark-new"
                    onClicked: win.textDialog.ask(qsTr("Save as preset"), "", function (name, desc) {
                        page.simple(["preset", "save", page.appId, name, "--description", desc], null, qsTr("Preset “%1” saved").arg(name))
                    }, true)
                }
                FormCard.FormButtonDelegate {
                    text: qsTr("Reset to recommended")
                    icon.name: "edit-undo"
                    onClicked: page.simple(["profile", "reset", page.appId], null, qsTr("Profile reset"))
                }
                FormCard.FormSwitchDelegate {
                    text: qsTr("Compatibility mode")
                    description: qsTr("This AppImage may require broader host access to function correctly. SAM can grant additional permissions, but this reduces isolation.")
                    checked: page.entry ? page.entry.profile.compatibility_mode : false
                    visible: win.config === null || win.config.compatibility.behavior !== "never"
                    onToggled: {
                        const on = checked
                        checked = Qt.binding(() => page.entry ? page.entry.profile.compatibility_mode : false)
                        if (on)
                            win.confirmDialog.ask(qsTr("Enable compatibility mode?"), description, () => page.simple(["compat", page.appId, "on"], null, qsTr("Compatibility mode on")), qsTr("Enable"))
                        else
                            page.simple(["compat", page.appId, "off"], null, qsTr("Compatibility mode off"))
                    }
                }
            }

            FormCard.FormHeader { title: qsTr("Sandbox backend"); visible: page.advanced }
            FormCard.FormCard {
                visible: page.advanced
                FormCard.FormComboBoxDelegate {
                    id: backendCombo
                    text: qsTr("Backend")
                    description: page.info && page.info.selection ? qsTr("Using %1: %2").arg(Util.backendLabels[page.info.selection.kind]).arg(page.info.selection.reason) : qsTr("No backend is available. See Diagnostics.")
                    model: [
                        { value: "auto", text: qsTr("Automatic (recommended)") },
                        { value: "bubblewrap", text: "Bubblewrap" },
                        { value: "bubblejail", text: qsTr("Bubblejail (better D-Bus filtering)") },
                        { value: "firejail", text: qsTr("Firejail (compatibility, setuid)") },
                        { value: "unsandboxed", text: qsTr("Unsandboxed (last resort)") }
                    ]
                    textRole: "text"
                    valueRole: "value"
                    currentIndex: page.entry ? Math.max(0, ["auto", "bubblewrap", "bubblejail", "firejail", "unsandboxed"].indexOf(page.entry.profile.backend)) : 0
                    onActivated: index => {
                        const v = model[index].value
                        currentIndex = Qt.binding(() => page.entry ? Math.max(0, ["auto", "bubblewrap", "bubblejail", "firejail", "unsandboxed"].indexOf(page.entry.profile.backend)) : 0)
                        page.setBackend(v)
                    }
                }
                Repeater {
                    model: page.info && page.info.selection ? page.info.selection.risks : []
                    delegate: FormCard.FormTextDelegate {
                        required property string modelData
                        icon.name: "data-warning"
                        text: modelData
                    }
                }
            }

            FormCard.FormHeader { title: qsTr("Generated sandbox command"); visible: page.advanced }
            FormCard.FormCard {
                visible: page.advanced
                FormCard.AbstractFormDelegate {
                    background: null
                    contentItem: ColumnLayout {
                        QQC2.TextArea {
                            Layout.fillWidth: true
                            Layout.preferredHeight: Kirigami.Units.gridUnit * 10
                            readOnly: true
                            wrapMode: Text.WrapAnywhere
                            font.family: "monospace"
                            font.pointSize: Math.max(7, Qt.application.font.pointSize - 1)
                            text: page.commandText
                        }
                        RowLayout {
                            QQC2.Button { text: qsTr("Copy"); icon.name: "edit-copy"; onClicked: { Backend.copyToClipboard(page.commandText); win.notify(qsTr("Copied")) } }
                            QQC2.Button { text: qsTr("Refresh"); icon.name: "view-refresh"; onClicked: page.loadCommand() }
                        }
                    }
                }
            }
            Item { Layout.preferredHeight: Kirigami.Units.gridUnit * 2 }
        }

        // ---------------------------------------------------- details tab
        ColumnLayout {
            id: details
            visible: page.tab === 1
            Layout.fillWidth: true
            spacing: 0

            FormCard.FormHeader { title: qsTr("Warnings"); visible: page.info !== null && page.info.warnings.length > 0 }
            FormCard.FormCard {
                visible: page.info !== null && page.info.warnings.length > 0
                FormCard.AbstractFormDelegate {
                    background: null
                    contentItem: WarningList { warnings: page.info ? page.info.warnings : [] }
                }
            }

            FormCard.FormHeader { title: qsTr("Application") }
            FormCard.FormCard {
                FormCard.FormTextDelegate { text: qsTr("Source"); description: page.entry ? Util.tildify(page.entry.source_path, win.home) : "" }
                FormCard.FormTextDelegate {
                    text: qsTr("SHA-256")
                    description: page.entry ? page.entry.source.sha256 : ""
                    trailing: QQC2.ToolButton { icon.name: "edit-copy"; onClicked: { Backend.copyToClipboard(page.entry.source.sha256); win.notify(qsTr("Checksum copied")) } }
                }
                FormCard.FormTextDelegate { text: qsTr("AppImage type"); description: page.entry ? (page.entry.appimage_type === "type2" ? qsTr("Type 2 (SquashFS)") : page.entry.appimage_type === "type1" ? qsTr("Type 1 (ISO 9660)") : qsTr("Unknown")) : "" }
                FormCard.FormTextDelegate { text: qsTr("Category"); description: page.entry ? Util.categoryLabel(page.entry.category) : "" }
                FormCard.FormTextDelegate {
                    text: qsTr("Extraction")
                    description: page.entry && page.entry.extraction
                        ? qsTr("%1 files, %2, via %3 (%4) on %5").arg(page.entry.extraction.file_count).arg(Backend.humanSize(page.entry.extraction.total_size)).arg(page.entry.extraction.method).arg(page.entry.extraction.compression).arg(Backend.formatTime(page.entry.extraction.extracted_at))
                        : qsTr("Not extracted")
                }
                FormCard.FormTextDelegate {
                    text: qsTr("Desktop launcher")
                    description: page.entry && page.entry.desktop_entry ? Util.tildify(page.entry.desktop_entry, win.home) : qsTr("Not installed")
                    trailing: QQC2.Button {
                        text: page.entry && page.entry.desktop_entry ? qsTr("Remove") : qsTr("Install")
                        onClicked: page.simple(["desktop", page.appId, page.entry.desktop_entry ? "remove" : "install"], null, qsTr("Launcher updated"))
                    }
                }
                FormCard.FormTextDelegate {
                    text: qsTr("Last launch")
                    description: page.entry && page.entry.last_launch ? Backend.formatTime(page.entry.last_launch.started_at) + " — " + page.entry.last_launch.summary : qsTr("Never")
                }
            }

            FormCard.FormHeader { title: qsTr("Dependencies"); visible: page.entry !== null && page.entry.detection !== null }
            FormCard.FormCard {
                id: depCard
                visible: page.entry !== null && page.entry.detection !== null
                readonly property var d: page.entry && page.entry.detection ? page.entry.detection : null
                FormCard.FormTextDelegate { text: qsTr("Toolkit"); description: depCard.d ? depCard.d.requirements.toolkit + " · " + depCard.d.arch + " · " + qsTr("%1 executables, %2 bundled libraries").arg(depCard.d.elf_count).arg(depCard.d.bundled_libraries) : "" }
                FormCard.FormTextDelegate {
                    text: qsTr("Compatibility")
                    description: depCard.d ? ({ "good": qsTr("Good"), "risk": qsTr("Compatibility risk"), "likely-broken": qsTr("Likely broken") })[depCard.d.compatibility] : ""
                }
                FormCard.FormTextDelegate {
                    text: qsTr("Detected needs")
                    description: {
                        const d = depCard.d
                        if (!d) return ""
                        const r = d.requirements, out = []
                        if (r.gpu) out.push(qsTr("GPU")); if (r.audio) out.push(qsTr("audio")); if (r.network) out.push(qsTr("network"))
                        if (r.x11) out.push("X11"); if (r.wayland) out.push("Wayland"); if (r.dbus) out.push("D-Bus")
                        return out.length ? out.join(", ") : qsTr("Nothing special")
                    }
                }
                FormCard.FormTextDelegate {
                    text: qsTr("Host libraries")
                    description: depCard.d ? depCard.d.missing.map(m => m.name + (m.host_available ? "" : " ✗")).join(", ") : ""
                    visible: page.advanced && depCard.d !== null && depCard.d.missing.length > 0
                }
                Repeater {
                    model: page.entry && page.entry.detection ? page.entry.detection.notes : []
                    delegate: FormCard.FormTextDelegate { required property string modelData; text: modelData; icon.name: "documentinfo" }
                }
            }

            FormCard.FormHeader { title: qsTr("Why these permissions"); visible: page.entry !== null && page.entry.recommendation_notes.length > 0 }
            FormCard.FormCard {
                visible: page.entry !== null && page.entry.recommendation_notes.length > 0
                Repeater {
                    model: page.entry ? page.entry.recommendation_notes : []
                    delegate: FormCard.FormTextDelegate { required property string modelData; text: modelData; icon.name: "help-hint" }
                }
            }

            readonly property var findings: page.entry && page.entry.last_launch ? (page.entry.last_launch.findings || []) : []
            readonly property var steps: page.info ? (page.info.repair_steps || []) : []

            FormCard.FormHeader { title: qsTr("What went wrong last time"); visible: details.findings.length > 0 }
            FormCard.FormCard {
                visible: details.findings.length > 0
                Repeater {
                    model: details.findings
                    delegate: FormCard.FormButtonDelegate {
                        required property var modelData
                        icon.name: modelData.action.kind === "none" ? "dialog-information" : "tools-wizard"
                        text: modelData.title
                        description: modelData.explanation
                        enabled: modelData.action.kind !== "none"
                        onClicked: page.applySuggestion(modelData, true, true)
                    }
                }
            }

            FormCard.FormHeader { title: qsTr("Make it work") }
            FormCard.FormCard {
                FormCard.FormButtonDelegate {
                    text: qsTr("Try the next fix and start")
                    icon.name: "media-playback-start"
                    visible: details.steps.length > 0
                    description: details.steps.length ? qsTr("Next: %1. %2").arg(details.steps[0].title).arg(details.steps[0].explanation) : ""
                    onClicked: page.applySuggestion(details.steps[0], true, true)
                }
                Repeater {
                    model: details.steps.slice(1)
                    delegate: FormCard.FormButtonDelegate {
                        required property var modelData
                        icon.name: "tools"
                        text: modelData.title
                        description: modelData.explanation
                        onClicked: page.applySuggestion(modelData, true, false)
                    }
                }
                FormCard.FormButtonDelegate {
                    text: qsTr("Undo all repairs")
                    icon.name: "edit-undo"
                    visible: page.entry !== null && page.entry.repair_backup !== null && page.entry.repair_backup !== undefined
                    description: page.entry ? qsTr("Applied: %1").arg((page.entry.repairs_applied || []).join(", ")) : ""
                    onClicked: page.simple(["repair", page.appId, "--undo"], null, qsTr("Repairs undone"))
                }
                FormCard.FormTextDelegate {
                    visible: details.steps.length === 0
                    text: qsTr("No more automatic fixes. The logs show the app's own messages.")
                }
            }

            FormCard.FormHeader { title: qsTr("Repair") }
            FormCard.FormCard {
                FormCard.FormButtonDelegate { text: qsTr("Files this app saved"); icon.name: "folder-open"; description: qsTr("The app's private folder, where it keeps settings and files it saved outside your granted folders."); onClicked: page.openPrivateFolder() }
                FormCard.FormButtonDelegate { text: qsTr("View logs"); icon.name: "view-list-text"; onClicked: page.tab = 2 }
                FormCard.FormButtonDelegate {
                    text: qsTr("Re-extract AppImage"); icon.name: "view-refresh"
                    description: qsTr("Unpack the AppImage again, e.g. after an update or a failed extraction.")
                    onClicked: win.reextract(page.appId, false, () => page.reload())
                }
                FormCard.FormButtonDelegate {
                    text: qsTr("Re-extract using the AppImage's own extractor…"); icon.name: "run-build"
                    description: qsTr("Fallback when static extraction fails. Runs code from the AppImage in a restricted sandbox.")
                    visible: page.advanced || (page.entry !== null && page.entry.extraction === null)
                    onClicked: win.confirmDialog.ask(qsTr("Run the AppImage's extractor?"), qsTr("This runs code from the AppImage inside a sandbox without network or access to your files. Only continue if you trust this file."), () => win.reextract(page.appId, true, () => page.reload()), qsTr("Continue"))
                }
                FormCard.FormButtonDelegate {
                    text: qsTr("Re-run dependency detection"); icon.name: "system-search"
                    onClicked: page.simple(["redetect", page.appId], null, qsTr("Dependency detection finished"))
                }
                FormCard.FormButtonDelegate {
                    text: qsTr("Reset profile to recommended"); icon.name: "edit-undo"
                    onClicked: page.simple(["profile", "reset", page.appId], null, qsTr("Profile reset"))
                }
                FormCard.FormButtonDelegate {
                    text: qsTr("Apply compatibility mode"); icon.name: "tools-wizard"
                    visible: page.entry !== null && !page.entry.profile.compatibility_mode && (win.config === null || win.config.compatibility.behavior !== "never")
                    onClicked: win.confirmDialog.ask(qsTr("Enable compatibility mode?"), qsTr("This AppImage may require broader host access to function correctly. SAM can grant additional permissions, but this reduces isolation."), () => page.simple(["compat", page.appId, "on"], null, qsTr("Compatibility mode on")), qsTr("Enable"))
                }
                FormCard.FormComboBoxDelegate {
                    text: qsTr("Switch backend")
                    model: [
                        { value: "auto", text: qsTr("Automatic") }, { value: "bubblewrap", text: "Bubblewrap" },
                        { value: "bubblejail", text: "Bubblejail" }, { value: "firejail", text: "Firejail" },
                        { value: "unsandboxed", text: qsTr("Unsandboxed") }
                    ]
                    textRole: "text"
                    valueRole: "value"
                    currentIndex: page.entry ? Math.max(0, ["auto", "bubblewrap", "bubblejail", "firejail", "unsandboxed"].indexOf(page.entry.profile.backend)) : 0
                    onActivated: index => {
                        const v = model[index].value
                        currentIndex = Qt.binding(() => page.entry ? Math.max(0, ["auto", "bubblewrap", "bubblejail", "firejail", "unsandboxed"].indexOf(page.entry.profile.backend)) : 0)
                        page.setBackend(v)
                    }
                }
                FormCard.FormButtonDelegate {
                    text: qsTr("Diagnose missing resources"); icon.name: "debug-run"
                    description: qsTr("Runs the app once under strace and suggests fixes; low-risk fixes are applied automatically.")
                    visible: page.advanced
                    onClicked: {
                        win.notify(qsTr("Starting diagnostic run (closes after 30 s)…"))
                        Backend.call(["diagnose", page.appId, "--apply"], function (r) {
                            if (!r.ok) { win.reportError(r); return }
                            const f = r.data.findings
                            win.notify(f.length ? qsTr("%1 finding(s), %2 fixed automatically. See the diagnose log.").arg(f.length).arg(r.data.applied) : qsTr("No missing resources found"))
                            page.logKind = "diagnose"
                            page.reload()
                        })
                    }
                }
                FormCard.FormButtonDelegate {
                    text: qsTr("Copy bug report"); icon.name: "edit-copy"
                    description: qsTr("A redacted report (home path, user and host names removed) for bug trackers.")
                    onClicked: Backend.call(["report", page.appId], function (r) {
                        if (r.ok) { Backend.copyToClipboard(r.data.report); win.notify(qsTr("Bug report copied")) } else win.reportError(r)
                    })
                }
                FormCard.FormButtonDelegate {
                    text: qsTr("Point to a moved AppImage…"); icon.name: "document-open"
                    onClicked: relocateDialog.open()
                }
            }
            Item { Layout.preferredHeight: Kirigami.Units.gridUnit * 2 }
        }

        // ---------------------------------------------------- logs tab
        ColumnLayout {
            visible: page.tab === 2
            Layout.fillWidth: true
            Layout.margins: Kirigami.Units.largeSpacing * 2
            RowLayout {
                QQC2.ComboBox {
                    model: [
                        { value: "launch", text: qsTr("Launch") }, { value: "extract", text: qsTr("Extraction") },
                        { value: "detect", text: qsTr("Dependency detection") }, { value: "diagnose", text: qsTr("Diagnostic runs") }
                    ]
                    textRole: "text"
                    valueRole: "value"
                    currentIndex: ["launch", "extract", "detect", "diagnose"].indexOf(page.logKind)
                    onActivated: { page.logKind = currentValue; page.loadLogs() }
                }
                Item { Layout.fillWidth: true }
                QQC2.Button { text: qsTr("Refresh"); icon.name: "view-refresh"; onClicked: page.loadLogs() }
                QQC2.Button { text: qsTr("Copy"); icon.name: "edit-copy"; onClicked: { Backend.copyToClipboard(page.logText); win.notify(qsTr("Log copied")) } }
            }
            QQC2.TextArea {
                Layout.fillWidth: true
                Layout.minimumHeight: Kirigami.Units.gridUnit * 24
                readOnly: true
                wrapMode: Text.WrapAnywhere
                font.family: "monospace"
                font.pointSize: Math.max(7, Qt.application.font.pointSize - 1)
                text: page.logText
            }
        }
    }

    PresetPickerDialog { id: presetPicker }

    // First-run check: shown once after "Create sandbox".
    Kirigami.Dialog {
        id: hintsDialog
        title: qsTr("Before you start %1").arg(page.title)
        preferredWidth: Kirigami.Units.gridUnit * 28
        standardButtons: Kirigami.Dialog.NoButton
        customFooterActions: [
            Kirigami.Action { text: qsTr("Done"); icon.name: "dialog-ok"; onTriggered: hintsDialog.close() }
        ]
        ColumnLayout {
            spacing: Kirigami.Units.largeSpacing
            QQC2.Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                text: qsTr("SAM picked strict permissions. These are the ones most likely to matter for this app. You can change everything later.")
            }
            Repeater {
                model: page.info ? page.info.hints : []
                delegate: RowLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    spacing: Kirigami.Units.largeSpacing
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2
                        QQC2.Label { text: modelData.title; font.bold: true; Layout.fillWidth: true; wrapMode: Text.WordWrap }
                        QQC2.Label { text: modelData.explanation; opacity: 0.75; Layout.fillWidth: true; wrapMode: Text.WordWrap }
                    }
                    QQC2.Button {
                        text: modelData.id === "files" ? qsTr("Allow Downloads") : qsTr("Allow")
                        onClicked: page.applySuggestion(modelData, false, false)
                    }
                }
            }
        }
    }

    Dialogs.FileDialog {
        id: relocateDialog
        title: qsTr("Locate the AppImage")
        nameFilters: [qsTr("AppImages (*.AppImage *.appimage)"), qsTr("All files (*)")]
        onAccepted: page.simple(["relocate", page.appId, Backend.urlToPath(selectedFile)], null, qsTr("Location updated"))
    }
}
