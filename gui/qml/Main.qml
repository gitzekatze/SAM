// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs as Dialogs
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

import SAM.Native
import "Util.js" as Util

Kirigami.ApplicationWindow {
    id: root

    title: "SAM"
    width: Kirigami.Units.gridUnit * 64
    height: Kirigami.Units.gridUnit * 42
    minimumWidth: Kirigami.Units.gridUnit * 22
    minimumHeight: Kirigami.Units.gridUnit * 20

    // ------------------------------------------------------------ state
    property var config: null
    property var catalog: ({})
    property var apps: []
    property bool appsLoaded: false
    /// Every AppImage SAM found (`sam-jail discover`).
    property var discovered: []
    /// Key of the selected row in the left column (app id or file path).
    property string selectedKey: ""
    /// Height of the pinned areas at the top of both columns.
    readonly property real topHeight: Kirigami.Units.gridUnit * 8
    readonly property string home: Backend.homeDir()

    function notify(text) {
        if (text)
            showPassiveNotification(text, 4000)
    }

    function reportError(r) {
        console.warn("sam-jail:", r.error)
        notify(r.error || qsTr("Something went wrong"))
    }

    function refreshApps(cb) {
        Backend.call(["list"], function (r) {
            if (r.ok)
                root.apps = r.data
            else
                reportError(r)
            Backend.call(["discover"], function (d) {
                if (d.ok)
                    root.discovered = d.data.apps
                root.appsLoaded = true
                if (cb)
                    cb()
            })
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
            if (!r.ok)
                reportError(r)
            loadConfig(cb)
        })
    }

    /// Add AppImage files (dropped or opened with SAM) to the locations and
    /// select the first one.
    function addFiles(paths) {
        const files = ((config && config.general.scan_files) || []).slice()
        for (const p of paths) {
            const t = Util.tildifyRaw(p, home)
            if (files.indexOf(t) < 0)
                files.push(t)
        }
        setConfig("general.scan_files", files, () => refreshApps(() => {
            const d = discovered.find(x => x.path === paths[0])
            if (d)
                selectRow({ key: d.sandboxed || d.path, id: d.sandboxed || "", path: d.path, sandboxed: !!d.sandboxed })
        }))
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

    /// Apply a preset with the compatibility check.
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
            notify(qsTr("Could not start sam-jail-run"))
    }

    /// Show one AppImage in the right column.
    function selectRow(row) {
        selectedKey = row.key
        while (pageStack.depth > 1)
            pageStack.pop()
        pageStack.push(Qt.resolvedUrl("AppPanel.qml"), row.sandboxed ? { appId: row.id, path: row.path || "" } : { appId: "", path: row.path })
    }

    /// Show SAM settings, presets or diagnostics in the right column.
    function showSection(section) {
        selectedKey = ""
        while (pageStack.depth > 1)
            pageStack.pop()
        const pages = { settings: "SettingsPage.qml", presets: "PresetsPage.qml", diagnostics: "DiagnosticsPage.qml" }
        if (pages[section])
            pageStack.push(Qt.resolvedUrl(pages[section]))
    }

    function openApp(id) {
        const a = apps.find(x => x.id === id)
        selectRow({ key: id, id: id, path: a ? a.source_path : "", sandboxed: true })
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
                if ((page === "app" || page === "app-repair") && Backend.startupApp)
                    openApp(Backend.startupApp)
                else if (page === "app" && root.apps.length)
                    openApp(root.apps[0].id)
                else if (page === "file" && root.discovered.length) {
                    const d = root.discovered.find(x => !x.sandboxed) || root.discovered[0]
                    selectRow({ key: d.path, id: "", path: d.path, sandboxed: false })
                } else if (page === "presets" || page === "settings" || page === "diagnostics")
                    showSection(page)
                else
                    pageStack.push(welcomeComponent)
                if (Backend.startupFiles.length)
                    root.addFiles(Backend.startupFiles)
            })
        })
    }

    pageStack.initialPage: AppListPage {}
    pageStack.globalToolBar.style: Kirigami.ApplicationHeaderStyle.ToolBar
    pageStack.defaultColumnWidth: Kirigami.Units.gridUnit * 26

    /// Right column before anything is selected.
    Component {
        id: welcomeComponent
        Kirigami.Page {
            title: qsTr("Welcome")
            Kirigami.PlaceholderMessage {
                anchors.centerIn: parent
                width: Math.min(parent.width - Kirigami.Units.gridUnit * 4, Kirigami.Units.gridUnit * 24)
                icon.source: "qrc:/qt/qml/SAM/icons/sam.svg"
                text: qsTr("Select an AppImage")
                explanation: qsTr("SAM lists the AppImages in the locations on the left. Pick one to see the settings SAM recommends, adjust them, and create a sandbox. Nothing is unpacked or run before you click Create sandbox.")
            }
        }
    }

    // -------------------------------------------------------- dialogs
    ConfirmDialog {
        id: confirm
    }


    // Exposed for pages.
    property alias confirmDialog: confirm

    // -------------------------------------------------------- drag & drop
    DropArea {
        id: drop
        anchors.fill: parent
        keys: ["text/uri-list"]
        onDropped: function (event) {
            root.addFiles(event.urls.map(u => Backend.urlToPath(u)))
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
                explanation: qsTr("It is added to the list on the left. Nothing is unpacked or run until you create a sandbox.")
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
                showPassiveNotification(qsTr("The app stopped with an error (code %1).").arg(code), 8000, qsTr("Fix it"), function () {
                    root.openApp(appId)
                })
        }
    }
}
