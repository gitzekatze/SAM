// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs as Dialogs
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.kirigamiaddons.formcard as FormCard

import SAM.Native
import "Util.js" as Util

/// Right column: one AppImage. A pinned header with the app and its main
/// button (Launch, or Create sandbox), then every setting, always visible.
/// Without a sandbox yet, the settings are SAM's recommendation and can be
/// adjusted before the sandbox is created.
Kirigami.ScrollablePage {
    id: page

    /// Sandboxed app id, or empty for an AppImage without a sandbox.
    property string appId: ""
    /// The AppImage file (used when there is no sandbox yet).
    property string path: ""

    readonly property var win: QQC2.ApplicationWindow.window
    readonly property bool sandboxed: appId !== ""

    // Sandboxed: `info` from the CLI. Not sandboxed: `preview`.
    property var info: null
    property var preview: null
    property var evaluation: null
    property var pendingPerms: null
    property bool hideUnsandboxedEntry: true
    property string logText: ""
    /// Why the settings could not be loaded (shown in the panel).
    property string loadError: ""
    property string commandText: ""

    readonly property var entry: info ? info.entry : null
    readonly property var summary: info ? info.app : null
    readonly property var found: win ? (win.discovered || []).find(d => d.path === (entry ? entry.source_path : path)) : null
    readonly property var selection: sandboxed ? (info ? info.selection : null) : (preview ? preview.selection : null)
    readonly property var perms: sandboxed ? (entry ? entry.profile.permissions : null) : pendingPerms
    readonly property string appName: sandboxed ? (summary ? summary.name : "") : (found ? found.name : path.split("/").pop())
    readonly property string iconPath: sandboxed ? (summary && summary.icon_path ? summary.icon_path : (found ? (found.icon || "") : "")) : (found ? (found.icon || "") : "")
    readonly property string filePath: sandboxed ? (entry ? entry.source_path : "") : path
    readonly property var findings: entry && entry.last_launch ? (entry.last_launch.findings || []) : []
    readonly property var steps: info ? (info.repair_steps || []) : []
    readonly property var hints: info ? (info.hints || []) : []

    /// The app's name; the toolbar above stays free of a second copy of it.
    readonly property string displayName: Util.plain(appName)
    title: ""

    // ------------------------------------------------ data
    function reload() {
        if (sandboxed) {
            Backend.call(["info", appId], function (r) {
                if (!r.ok) { page.loadError = r.error || qsTr("Unknown error"); win.reportError(r); return }
                page.loadError = ""
                page.info = r.data
                evaluate(r.data.entry.profile.permissions)
                loadLogs()
                Backend.call(["command", appId], c => page.commandText = c.ok ? c.data.command : (c.error || ""))
            })
        } else {
            Backend.call(["preview", path], function (r) {
                if (!r.ok) { page.loadError = r.error || qsTr("Unknown error"); win.reportError(r); return }
                page.loadError = ""
                page.preview = r.data
                page.pendingPerms = r.data.permissions
                page.evaluation = { risk: r.data.risk, warnings: r.data.warnings }
            })
        }
    }
    function evaluate(p) {
        Backend.call(["evaluate", appId], r => { if (r.ok) page.evaluation = r.data }, JSON.stringify(p))
    }
    /// Re-evaluate the adjusted settings of an AppImage without a sandbox.
    function evaluatePending() {
        Backend.call(["preview", path, "--permissions-stdin"], function (r) {
            if (!r.ok) { win.reportError(r); return }
            page.preview = r.data
            page.evaluation = { risk: r.data.risk, warnings: r.data.warnings }
        }, JSON.stringify(pendingPerms))
    }
    function loadLogs() {
        Backend.call(["logs", appId, "--kind", "launch", "--tail", "200"], r => page.logText = r.ok ? r.data.text : qsTr("No logs yet."))
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
    function onPermsEdited(p) {
        if (sandboxed) {
            evaluate(p)
            Backend.call(["profile", "set", appId], r => { if (!r.ok) win.reportError(r); reload(); win.refreshApps() }, JSON.stringify(p))
        } else {
            pendingPerms = p
            evaluatePending()
        }
    }
    function createSandbox() {
        const args = ["add", path, "--accept", "--permissions-stdin"]
        if (hideUnsandboxedEntry && found && found.menu_entries.length)
            args.push("--hide-duplicates")
        win.notify(qsTr("Creating the sandbox for %1…").arg(page.displayName))
        Backend.call(args, function (r) {
            if (!r.ok) { win.reportError(r); return }
            win.refreshApps(() => win.selectRow({ key: r.data.entry.id, id: r.data.entry.id, path: r.data.entry.source_path, sandboxed: true }))
            if (r.data.needs_fallback_consent)
                win.confirmDialog.ask(qsTr("Static extraction failed"),
                    qsTr("SAM could not unpack %1 without running it. It can try the AppImage's own extractor instead. That runs code from the AppImage, inside a sandbox with no network and no access to your files.\n\nOnly continue if you trust where this file came from.").arg(page.displayName),
                    () => win.reextract(r.data.entry.id, true), qsTr("Use the AppImage's extractor"))
            else
                win.notify(qsTr("Sandbox created for %1").arg(page.displayName))
        }, JSON.stringify(pendingPerms))
    }
    /// Apply a hint (`hints --apply`) or a repair step / finding (`repair --apply`).
    function applySuggestion(sug, asRepair, thenRun) {
        const run = () => page.simple(asRepair ? ["repair", appId, "--apply", sug.id] : ["hints", appId, "--apply", sug.id], function (r) {
            if (r.ok && thenRun)
                win.launch(appId)
        }, qsTr("Applied: %1").arg(sug.title))
        if (sug.from_app_output)
            win.confirmDialog.ask(qsTr("Apply “%1”?").arg(sug.title),
                qsTr("This suggestion is based on messages the app printed itself. A malicious app can print messages to get more access.") + "\n\n" + sug.explanation,
                run, qsTr("Apply"))
        else if (sug.risk === "high" || sug.risk === "dangerous" || sug.action.kind === "compat")
            win.confirmDialog.ask(qsTr("Apply “%1”?").arg(sug.title), sug.explanation, run, qsTr("Apply"))
        else
            run()
    }
    function openPrivateFolder() {
        if (info && info.private_home)
            Qt.openUrlExternally(Backend.pathToUrl(info.private_home))
    }

    Component.onCompleted: reload()

    // ------------------------------------------------ secondary actions
    actions: [
        Kirigami.Action {
            text: qsTr("Files this app saved")
            icon.name: "folder-open"
            displayHint: Kirigami.DisplayHint.AlwaysHide
            visible: page.sandboxed
            onTriggered: page.openPrivateFolder()
        },
        Kirigami.Action {
            text: qsTr("Reset to recommended")
            icon.name: "edit-undo"
            displayHint: Kirigami.DisplayHint.AlwaysHide
            onTriggered: page.sandboxed ? page.simple(["profile", "reset", page.appId], null, qsTr("Settings reset")) : page.reload()
        },
        Kirigami.Action {
            text: qsTr("Re-extract AppImage")
            icon.name: "view-refresh"
            displayHint: Kirigami.DisplayHint.AlwaysHide
            visible: page.sandboxed
            onTriggered: win.reextract(page.appId, false, () => page.reload())
        },
        Kirigami.Action {
            text: qsTr("Remove sandbox…")
            icon.name: "edit-delete"
            displayHint: Kirigami.DisplayHint.AlwaysHide
            visible: page.sandboxed
            onTriggered: win.confirmDialog.ask(qsTr("Remove the sandbox for %1?").arg(page.displayName),
                qsTr("The extracted copy, SAM's menu entry, logs and the app's private settings are deleted. The AppImage file itself is kept, and any menu entry SAM hid is shown again."),
                () => Backend.call(["remove", page.appId], function (r) {
                    if (!r.ok) { win.reportError(r); return }
                    win.notify((r.data.warnings || []).length ? qsTr("Removed the sandbox, but: %1").arg(Util.plain(r.data.warnings.join("; "))) : qsTr("Removed the sandbox for %1").arg(page.displayName))
                    win.refreshApps(() => win.selectRow({ key: page.filePath, id: "", path: page.filePath, sandboxed: false }))
                }), qsTr("Remove sandbox"))
        }
    ]

    // ------------------------------------------------ pinned header
    header: QQC2.Pane {
        implicitHeight: win ? win.topHeight : Kirigami.Units.gridUnit * 9
        padding: Kirigami.Units.largeSpacing
        Kirigami.Theme.colorSet: Kirigami.Theme.Window
        Kirigami.Theme.inherit: false
        background: Rectangle {
            color: Kirigami.Theme.backgroundColor
            Kirigami.Separator { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom }
        }
        contentItem: RowLayout {
            spacing: Kirigami.Units.largeSpacing * 2
            AppIcon {
                path: page.iconPath
                Layout.preferredWidth: Kirigami.Units.iconSizes.huge
                Layout.preferredHeight: Kirigami.Units.iconSizes.huge
                Layout.leftMargin: Kirigami.Units.largeSpacing
            }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: Kirigami.Units.smallSpacing
                Kirigami.Heading {
                    level: 1
                    font.pointSize: Math.round(Qt.application.font.pointSize * 1.6)
                    font.weight: Font.Bold
                    text: page.displayName
                    textFormat: Text.PlainText
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                }
                QQC2.Label {
                    text: Util.tildify(page.filePath, win ? win.home : "")
                    textFormat: Text.PlainText
                    elide: Text.ElideMiddle
                    opacity: 0.6
                    font.pointSize: Util.smallPointSize(Qt.application.font)
                    Layout.fillWidth: true
                }
                RowLayout {
                    spacing: Kirigami.Units.smallSpacing
                    Layout.topMargin: Kirigami.Units.smallSpacing
                    Pill {
                        text: page.sandboxed ? qsTr("Sandboxed") : qsTr("Not sandboxed")
                        iconName: page.sandboxed ? "security-high" : "security-low"
                        tone: page.sandboxed ? Kirigami.Theme.positiveTextColor : Kirigami.Theme.disabledTextColor
                    }
                    RiskChip {
                        level: page.evaluation ? page.evaluation.risk.level : "low"
                        score: page.evaluation ? page.evaluation.risk.score : -1
                    }
                    Pill {
                        text: page.selection ? qsTr("Bubblewrap") : qsTr("Sandbox unavailable")
                        tone: page.selection ? Kirigami.Theme.disabledTextColor : Kirigami.Theme.negativeTextColor
                        QQC2.ToolTip.visible: pillHover.hovered
                        QQC2.ToolTip.text: page.selection ? qsTr("Runs in a Bubblewrap sandbox") : qsTr("Bubblewrap cannot run on this system; see Diagnostics")
                        HoverHandler { id: pillHover }
                    }
                }
            }
            PrimaryButton {
                Layout.alignment: Qt.AlignVCenter
                Layout.rightMargin: Kirigami.Units.largeSpacing
                text: page.sandboxed ? qsTr("Launch") : qsTr("Create sandbox")
                icon.name: page.sandboxed ? "media-playback-start" : "security-high"
                enabled: page.sandboxed ? (page.summary !== null && page.summary.badge !== "missing") : page.pendingPerms !== null
                onClicked: page.sandboxed ? win.launch(page.appId) : page.createSandbox()
            }
        }
    }

    // ------------------------------------------------ settings
    ColumnLayout {
        spacing: 0

        // Notices: only when there is something to say.
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            Layout.maximumWidth: Kirigami.Units.gridUnit * 30
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: Kirigami.Units.largeSpacing
            visible: page.loadError !== ""
            type: Kirigami.MessageType.Error
            text: qsTr("The settings could not be loaded: %1").arg(Util.plain(page.loadError))
            actions: [Kirigami.Action { text: qsTr("Try again"); icon.name: "view-refresh"; onTriggered: page.reload() }]
        }
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            Layout.maximumWidth: Kirigami.Units.gridUnit * 30
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: Kirigami.Units.largeSpacing
            visible: page.loadError === "" && page.perms === null
            type: Kirigami.MessageType.Information
            text: qsTr("Loading settings…")
        }
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            Layout.maximumWidth: Kirigami.Units.gridUnit * 30
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: Kirigami.Units.largeSpacing
            visible: !page.sandboxed
            type: Kirigami.MessageType.Information
            text: qsTr("Not sandboxed yet. These are the settings SAM recommends for this app. Adjust them below, then click Create sandbox. Nothing is unpacked or run before that.")
        }
        FormCard.FormCard {
            Layout.topMargin: Kirigami.Units.largeSpacing
            visible: page.found !== null && page.found !== undefined && (page.found.menu_entries || []).length > 0 && !page.sandboxed
            FormCard.FormSwitchDelegate {
                text: qsTr("Hide the unsandboxed menu entry")
                description: qsTr("This AppImage already has a menu entry that starts it without a sandbox. SAM hides it when the sandbox is created and puts it back if you remove the sandbox.")
                checked: page.hideUnsandboxedEntry
                onToggled: page.hideUnsandboxedEntry = checked
            }
        }
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            Layout.maximumWidth: Kirigami.Units.gridUnit * 30
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: Kirigami.Units.largeSpacing
            visible: page.summary !== null && (page.summary.badge === "stale" || page.summary.badge === "broken" || page.summary.badge === "missing")
            type: page.summary && page.summary.badge === "stale" ? Kirigami.MessageType.Warning : Kirigami.MessageType.Error
            text: page.summary === null ? "" : page.summary.badge === "stale" ? qsTr("The AppImage changed since it was extracted. Re-extract it to use the new version.")
                : page.summary.badge === "missing" ? qsTr("The AppImage file is missing. Point SAM at its new location, or remove the sandbox.")
                : Util.plain(page.entry && page.entry.last_error ? page.entry.last_error : qsTr("This app cannot start."))
            actions: [
                Kirigami.Action { text: qsTr("Re-extract"); icon.name: "view-refresh"; visible: page.summary !== null && page.summary.badge !== "missing"; onTriggered: win.reextract(page.appId, false, () => page.reload()) },
                Kirigami.Action { text: qsTr("Locate…"); icon.name: "document-open"; visible: page.summary !== null && page.summary.badge === "missing"; onTriggered: relocateDialog.open() }
            ]
        }
        Kirigami.InlineMessage {
            Layout.fillWidth: true
            Layout.maximumWidth: Kirigami.Units.gridUnit * 30
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: Kirigami.Units.largeSpacing
            visible: page.entry !== null && (page.entry.pending_changes || []).length > 0
            type: Kirigami.MessageType.Information
            text: page.entry ? qsTr("The updated AppImage likely needs: %1. Your settings were kept.").arg((page.entry.pending_changes || []).join(", ")) : ""
            actions: [Kirigami.Action { text: qsTr("Got it"); onTriggered: page.simple(["review", page.appId], null, "") }]
        }

        // First-start checks and last problems.
        FormCard.FormHeader { title: qsTr("Worth checking"); visible: page.hints.length > 0 }
        FormCard.FormCard {
            visible: page.hints.length > 0
            Repeater {
                model: page.hints
                delegate: FormCard.FormButtonDelegate {
                    required property var modelData
                    icon.name: "dialog-information"
                    text: modelData.title
                    description: modelData.explanation
                    onClicked: page.applySuggestion(modelData, false, false)
                }
            }
        }
        FormCard.FormHeader { title: qsTr("What went wrong last time"); visible: page.findings.length > 0 }
        FormCard.FormCard {
            visible: page.findings.length > 0
            Repeater {
                model: page.findings
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

        // Presets (sandboxed apps).
        FormCard.FormHeader { title: qsTr("Preset"); visible: page.sandboxed }
        FormCard.FormCard {
            visible: page.sandboxed
            FormCard.AbstractFormDelegate {
                background: null
                Layout.fillWidth: true
                contentItem: RowLayout {
                    spacing: Kirigami.Units.largeSpacing
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: Kirigami.Units.smallSpacing
                        QQC2.Label { text: qsTr("Start from a preset"); Layout.fillWidth: true; wrapMode: Text.Wrap }
                        QQC2.Label {
                            text: page.entry && page.entry.profile.preset ? qsTr("Current settings come from “%1”.").arg(Util.plain(page.entry.profile.preset)) : qsTr("Replaces the settings below.")
                            color: Kirigami.Theme.disabledTextColor
                            wrapMode: Text.Wrap
                            Layout.fillWidth: true
                        }
                    }
                    QQC2.ComboBox {
                        id: presetCombo
                        property var presets: []
                        model: [{ name: qsTr("Choose…") }].concat(presets)
                        textRole: "name"
                        Layout.preferredWidth: Math.max(implicitWidth, Kirigami.Units.gridUnit * 9)
                        Component.onCompleted: Backend.call(["preset", "list"], r => { if (r.ok) presets = r.data })
                        onActivated: index => {
                            if (index > 0)
                                win.applyPreset(presets[index - 1].name, page.appId, () => page.reload())
                            currentIndex = 0
                        }
                    }
                }
            }
        }

        PermissionsEditor {
            Layout.fillWidth: true
            perms: page.perms
            recommended: page.sandboxed ? (page.entry ? page.entry.recommended : null) : (page.preview ? page.preview.recommended : null)
            evaluation: page.evaluation
            onEdited: newPerms => page.onPermsEdited(newPerms)
        }

        // Making it work (sandboxed apps).
        FormCard.FormHeader { title: qsTr("Troubleshooting"); visible: page.sandboxed }
        FormCard.FormCard {
            visible: page.sandboxed
            FormCard.FormTextDelegate {
                text: qsTr("Last start")
                description: page.entry && page.entry.last_launch
                    ? Backend.formatTime(page.entry.last_launch.started_at) + " — " + Util.plain(page.entry.last_launch.summary)
                      + (page.entry.last_launch.enforcement ? "\n" + qsTr("Enforced: %1").arg(Util.plain(page.entry.last_launch.enforcement)) : "")
                    : qsTr("Not started yet")
            }
            FormCard.FormButtonDelegate {
                text: qsTr("Try the next fix and start")
                icon.name: "media-playback-start"
                visible: page.steps.length > 0
                description: page.steps.length ? qsTr("Next: %1. %2").arg(page.steps[0].title).arg(page.steps[0].explanation) : ""
                onClicked: page.applySuggestion(page.steps[0], true, true)
            }
            Repeater {
                model: page.steps.slice(1)
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
            FormCard.FormButtonDelegate {
                text: qsTr("Files this app saved")
                icon.name: "folder-open"
                description: qsTr("The app's private folder, where it keeps settings and files it saved outside your granted folders.")
                onClicked: page.openPrivateFolder()
            }
            FormCard.FormButtonDelegate {
                text: qsTr("Diagnose missing resources")
                icon.name: "debug-run"
                description: qsTr("Runs the app once under strace (if installed) and suggests fixes.")
                onClicked: {
                    win.notify(qsTr("Starting a diagnostic run (closes after 30 s)…"))
                    Backend.call(["diagnose", page.appId, "--apply"], r => { if (!r.ok) win.reportError(r); page.reload() })
                }
            }
            FormCard.FormButtonDelegate {
                text: qsTr("Copy bug report")
                icon.name: "edit-copy"
                description: qsTr("A redacted report (home path, user and host names removed).")
                onClicked: Backend.call(["report", page.appId], r => { if (r.ok) { Backend.copyToClipboard(r.data.report); win.notify(qsTr("Bug report copied")) } else win.reportError(r) })
            }
        }

        FormCard.FormHeader { title: qsTr("Details"); visible: page.sandboxed }
        FormCard.FormCard {
            visible: page.sandboxed
            FormCard.FormTextDelegate { text: qsTr("Category"); description: page.entry ? Util.categoryLabel(page.entry.category) : "" }
            FormCard.FormTextDelegate { text: qsTr("AppImage type"); description: page.entry ? page.entry.appimage_type : "" }
            FormCard.FormTextDelegate {
                text: qsTr("Extraction")
                description: page.entry && page.entry.extraction ? qsTr("%1 files via %2").arg(page.entry.extraction.file_count).arg(page.entry.extraction.method) : qsTr("Not extracted")
            }
            FormCard.FormSwitchDelegate {
                text: qsTr("Menu entry")
                description: page.entry && page.entry.desktop_entry ? Util.tildify(page.entry.desktop_entry, win.home) : qsTr("No menu entry")
                checked: page.entry !== null && !!page.entry.desktop_entry
                onToggled: page.simple(["desktop", page.appId, checked ? "install" : "remove"], null, qsTr("Menu entry updated"))
            }
            FormCard.FormTextDelegate { text: qsTr("SHA-256"); description: page.entry ? page.entry.source.sha256 : "" }
        }

        FormCard.FormHeader { title: qsTr("Sandbox command"); visible: page.sandboxed }
        FormCard.FormCard {
            visible: page.sandboxed
            FormCard.AbstractFormDelegate {
                background: null
                contentItem: QQC2.TextArea {
                    readOnly: true
                    wrapMode: Text.WrapAnywhere
                    textFormat: TextEdit.PlainText
                    font.family: "monospace"
                    font.pointSize: Math.max(7, Qt.application.font.pointSize - 1)
                    text: page.commandText
                }
            }
        }

        FormCard.FormHeader { title: qsTr("Log of the last start"); visible: page.sandboxed }
        FormCard.FormCard {
            visible: page.sandboxed
            FormCard.AbstractFormDelegate {
                background: null
                contentItem: ColumnLayout {
                    RowLayout {
                        Item { Layout.fillWidth: true }
                        QQC2.Button { text: qsTr("Refresh"); icon.name: "view-refresh"; onClicked: page.loadLogs() }
                        QQC2.Button { text: qsTr("Copy"); icon.name: "edit-copy"; onClicked: { Backend.copyToClipboard(page.logText); win.notify(qsTr("Log copied")) } }
                    }
                    QQC2.TextArea {
                        Layout.fillWidth: true
                        Layout.preferredHeight: Kirigami.Units.gridUnit * 14
                        readOnly: true
                        wrapMode: Text.WrapAnywhere
                        textFormat: TextEdit.PlainText
                        font.family: "monospace"
                        font.pointSize: Math.max(7, Qt.application.font.pointSize - 1)
                        text: page.logText
                    }
                }
            }
        }
        Item { Layout.preferredHeight: Kirigami.Units.gridUnit * 2 }
    }

    Dialogs.FileDialog {
        id: relocateDialog
        title: qsTr("Locate the AppImage")
        nameFilters: [qsTr("AppImages (*.AppImage *.appimage)"), qsTr("All files (*)")]
        onAccepted: page.simple(["relocate", page.appId, Backend.urlToPath(selectedFile)], null, qsTr("Location updated"))
    }
}
