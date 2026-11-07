// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs as Dialogs
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

import Appseal.Native
import "Util.js" as Util

Kirigami.ApplicationWindow {
    id: root

    title: "Appseal"
    width: Kirigami.Units.gridUnit * 64
    height: Kirigami.Units.gridUnit * 42
    minimumWidth: Kirigami.Units.gridUnit * 22
    minimumHeight: Kirigami.Units.gridUnit * 20

    // ------------------------------------------------------------ state
    property var config: null
    property var catalog: ({})
    property var apps: []
    property bool appsLoaded: false
    property string currentSection: "apps"
    readonly property bool advanced: config !== null && config.general.ui_mode === "advanced"
    readonly property string home: Backend.homeDir()

    function notify(text) {
        showPassiveNotification(text, 4000)
    }

    function reportError(r) {
        notify(r.error || qsTr("Something went wrong"))
    }

    function refreshApps(cb) {
        Backend.call(["list"], function (r) {
            if (r.ok) {
                root.apps = r.data
                root.appsLoaded = true
            } else {
                reportError(r)
            }
            if (cb)
                cb()
        })
    }

    function loadConfig(cb) {
        Backend.call(["config", "show"], function (r) {
            if (r.ok) {
                root.config = r.data
                Themes.apply(r.data.general.theme)
            }
            if (cb)
                cb()
        })
    }

    function setConfig(key, value, cb) {
        const v = (typeof value === "string") ? value : JSON.stringify(value)
        Backend.call(["config", "set", key, v], function (r) {
            if (!r.ok) {
                reportError(r)
            }
            loadConfig(cb)
        })
    }

    function addAppImage(path, consent) {
        const args = ["add", path]
        if (consent)
            args.push("--allow-fallback")
        notify(qsTr("Adding %1…").arg(path.split("/").pop()))
        Backend.call(args, function (r) {
            if (!r.ok) {
                reportError(r)
                return
            }
            refreshApps()
            const e = r.data.entry
            if (r.data.needs_fallback_consent) {
                confirm.ask(qsTr("Static extraction failed"),
                    qsTr("Appseal could not unpack %1 without running it. It can try the AppImage's own extractor instead. That runs code from the AppImage, inside a sandbox with no network and no access to your files.\n\nOnly continue if you trust where this file came from.").arg(e.name),
                    function () { reextract(e.id, true) }, qsTr("Use the AppImage's extractor"))
                return
            }
            if (r.data.relocated) {
                notify(qsTr("%1 was already known; its new location was saved.").arg(e.name))
                return
            }
            notify(qsTr("Added %1. Review its permissions.").arg(e.name))
            openApp(e.id)
        })
    }

    function reextract(id, consent, cb) {
        const args = ["reextract", id]
        if (consent)
            args.push("--allow-fallback")
        Backend.call(args, function (r) {
            if (r.ok) {
                notify(qsTr("Re-extracted"))
                if (r.data.pending_changes && r.data.pending_changes.length)
                    notify(qsTr("The update likely needs: %1").arg(r.data.pending_changes.join(", ")))
            } else {
                reportError(r)
            }
            refreshApps()
            if (cb)
                cb(r)
        })
    }

    /// Apply a preset with the compatibility check from whitepaper §2.18.
    function applyPreset(name, appId, cb) {
        Backend.call(["preset", "apply", name, appId], function (r) {
            if (!r.ok) {
                reportError(r)
                return
            }
            if (r.data.applied) {
                notify(qsTr("Applied “%1”").arg(name))
                refreshApps()
                if (cb) cb()
                return
            }
            const c = r.data.check
            let text = ""
            if (c.removes_needed.length)
                text += qsTr("This preset removes permissions the app likely needs: %1.").arg(c.removes_needed.join(", ")) + "\n\n"
            if (c.adds_dangerous.length)
                text += qsTr("It adds high-risk permissions: %1.").arg(c.adds_dangerous.join(", ")) + "\n\n"
            text += qsTr("Risk changes from %1 to %2.").arg(c.risk_before).arg(c.risk_after)
            confirm.ask(qsTr("Apply “%1” anyway?").arg(name), text, function () {
                Backend.call(["preset", "apply", name, appId, "--yes"], function (r2) {
                    if (r2.ok) notify(qsTr("Applied “%1”").arg(name))
                    else reportError(r2)
                    refreshApps()
                    if (cb) cb()
                })
            }, qsTr("Apply"))
        })
    }

    function launch(id) {
        if (Backend.launch(id))
            notify(qsTr("Starting in sandbox…"))
        else
            notify(qsTr("Could not start appseal-run"))
    }

    function showSection(section) {
        currentSection = section
        pageStack.clear()
        switch (section) {
        case "apps": pageStack.push(dashboardComponent); break
        case "presets": pageStack.push(Qt.resolvedUrl("PresetsPage.qml")); break
        case "settings": pageStack.push(Qt.resolvedUrl("SettingsPage.qml")); break
        case "diagnostics": pageStack.push(Qt.resolvedUrl("DiagnosticsPage.qml")); break
        }
    }

    function openApp(id) {
        if (currentSection !== "apps")
            showSection("apps")
        while (pageStack.depth > 1)
            pageStack.pop()
        pageStack.push(Qt.resolvedUrl("AppPage.qml"), { appId: id })
    }

    // -------------------------------------------------------- startup
    Component.onCompleted: {
        Backend.call(["permissions"], function (r) {
            if (!r.ok)
                return
            const m = {}
            for (const p of r.data)
                m[p.key] = p
            root.catalog = m
        })
        loadConfig(function () {
            refreshApps(function () {
                const page = Backend.startupPage
                if (page === "app" && Backend.startupApp)
                    openApp(Backend.startupApp)
                else if (page === "app" && root.apps.length)
                    openApp(root.apps[0].id)
                else if (page === "presets" || page === "settings" || page === "diagnostics")
                    showSection(page)
                else if (page === "onboarding")
                    onboarding.open()
                for (const f of Backend.startupFiles)
                    root.addAppImage(f, false)
                Backend.call(["onboarding"], function (r) {
                    if (r.ok && !r.data.done && page === "")
                        onboarding.open()
                })
                if (root.config && root.config.general.automatic_scanning && page === "")
                    scanDialog.scan(true)
            })
        })
    }

    // -------------------------------------------------------- drawer
    globalDrawer: Kirigami.GlobalDrawer {
        id: drawer
        modal: !root.wideScreen
        collapsible: true
        collapsed: !root.wideScreen
        showHeaderWhenCollapsed: true
        width: Kirigami.Units.gridUnit * 13

        header: Kirigami.AbstractApplicationHeader {
            contentItem: RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Kirigami.Units.largeSpacing
                spacing: Kirigami.Units.smallSpacing
                Kirigami.Icon {
                    source: "qrc:/qt/qml/Appseal/icons/appseal.svg"
                    implicitWidth: Kirigami.Units.iconSizes.medium
                    implicitHeight: implicitWidth
                }
                Kirigami.Heading {
                    level: 2
                    text: "Appseal"
                    visible: !drawer.collapsed
                    Layout.fillWidth: true
                }
            }
        }

        actions: [
            Kirigami.Action {
                text: qsTr("Applications")
                icon.name: "view-list-icons"
                checkable: true
                checked: root.currentSection === "apps"
                onTriggered: root.showSection("apps")
            },
            Kirigami.Action {
                text: qsTr("Presets")
                icon.name: "bookmarks"
                checkable: true
                checked: root.currentSection === "presets"
                onTriggered: root.showSection("presets")
            },
            Kirigami.Action {
                text: qsTr("Diagnostics")
                icon.name: "tools-report-bug"
                checkable: true
                checked: root.currentSection === "diagnostics"
                onTriggered: root.showSection("diagnostics")
            },
            Kirigami.Action {
                text: qsTr("Settings")
                icon.name: "configure"
                checkable: true
                checked: root.currentSection === "settings"
                onTriggered: root.showSection("settings")
            },
            Kirigami.Action { separator: true },
            Kirigami.Action {
                text: qsTr("Add AppImage…")
                icon.name: "list-add"
                onTriggered: fileDialog.open()
            },
            Kirigami.Action {
                text: qsTr("Scan folders")
                icon.name: "edit-find"
                onTriggered: scanDialog.scan(false)
            },
            Kirigami.Action {
                text: qsTr("Welcome tour")
                icon.name: "help-about"
                onTriggered: onboarding.open()
            }
        ]

        footer: QQC2.ToolButton {
            visible: !drawer.collapsed
            text: root.advanced ? qsTr("Advanced mode") : qsTr("Simple mode")
            icon.name: root.advanced ? "configure-toolbars" : "view-media-favorite"
            checkable: true
            checked: root.advanced
            onToggled: root.setConfig("general.ui_mode", checked ? "advanced" : "simple")
            QQC2.ToolTip.visible: hovered
            QQC2.ToolTip.text: qsTr("Advanced mode shows backends, D-Bus rules, custom mounts, the generated sandbox command and diagnostics.")
        }
    }

    pageStack.initialPage: dashboardComponent
    pageStack.globalToolBar.style: Kirigami.ApplicationHeaderStyle.ToolBar
    pageStack.defaultColumnWidth: Kirigami.Units.gridUnit * 26

    Component {
        id: dashboardComponent
        DashboardPage {}
    }

    // -------------------------------------------------------- dialogs
    Dialogs.FileDialog {
        id: fileDialog
        title: qsTr("Add AppImage")
        nameFilters: [qsTr("AppImages (*.AppImage *.appimage)"), qsTr("All files (*)")]
        currentFolder: Backend.pathToUrl(root.home)
        onAccepted: root.addAppImage(Backend.urlToPath(selectedFile), false)
    }

    ScanDialog {
        id: scanDialog
    }

    OnboardingDialog {
        id: onboarding
    }

    ConfirmDialog {
        id: confirm
    }

    TextInputDialog {
        id: textInput
    }

    // Exposed for pages.
    property alias confirmDialog: confirm
    property alias textDialog: textInput
    property alias addDialog: fileDialog
    property alias scanner: scanDialog

    // -------------------------------------------------------- drag & drop
    DropArea {
        id: drop
        anchors.fill: parent
        keys: ["text/uri-list"]
        onDropped: function (event) {
            for (const u of event.urls)
                root.addAppImage(Backend.urlToPath(u), false)
            event.acceptProposedAction()
        }

        Rectangle {
            anchors.fill: parent
            visible: drop.containsDrag
            color: Qt.rgba(Kirigami.Theme.highlightColor.r, Kirigami.Theme.highlightColor.g, Kirigami.Theme.highlightColor.b, 0.18)
            border.color: Kirigami.Theme.highlightColor
            border.width: 3
            radius: Kirigami.Units.cornerRadius
            z: 1000

            Kirigami.PlaceholderMessage {
                anchors.centerIn: parent
                icon.name: "document-import"
                text: qsTr("Drop an AppImage to add it")
                explanation: qsTr("Appseal will unpack it without running it and suggest safe permissions.")
            }
        }
    }

    QQC2.BusyIndicator {
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.margins: Kirigami.Units.largeSpacing
        running: Backend.busy
        visible: running
        z: 999
    }

    Connections {
        target: Backend
        function onAppFinished(appId, code) {
            root.refreshApps()
            if (code !== 0)
                root.notify(qsTr("The app exited with code %1. Open it in Appseal → Details → Logs to see why.").arg(code))
        }
    }
}
