// SPDX-License-Identifier: GPL-3.0-or-later
.pragma library

function clone(o) {
    return JSON.parse(JSON.stringify(o))
}

function getPath(obj, key) {
    const parts = key.split(".")
    let cur = obj
    for (let i = 0; i < parts.length; i++) {
        if (cur === undefined || cur === null)
            return undefined
        cur = cur[parts[i]]
    }
    return cur
}

function setPath(obj, key, value) {
    const parts = key.split(".")
    let cur = obj
    for (let i = 0; i < parts.length - 1; i++) {
        if (cur[parts[i]] === undefined || cur[parts[i]] === null)
            cur[parts[i]] = {}
        cur = cur[parts[i]]
    }
    cur[parts[parts.length - 1]] = value
}

const badgeLabels = {
    "ready": "Ready",
    "needs-review": "Needs Review",
    "compatibility-risk": "Compatibility Risk",
    "stale": "Stale",
    "broken": "Broken",
    "unsafe": "Unsafe",
    "missing": "Missing"
}

const categoryLabels = {
    "browser": "Browser",
    "media-player": "Media player",
    "image-editor": "Image editor",
    "video-editor": "Video editor",
    "audio-editor": "Audio editor",
    "game": "Game",
    "text-editor": "Text editor",
    "office": "Office",
    "terminal": "Terminal",
    "development": "Development",
    "communication": "Communication",
    "utility": "Utility"
}

function categoryLabel(c) {
    return categoryLabels[c] || (c ? c : "Unknown")
}

function riskLabel(r) {
    if (!r)
        return ""
    return r.charAt(0).toUpperCase() + r.slice(1)
}

function iconUrl(path) {
    return path ? "file://" + path : ""
}

/// Text from AppImages, apps or file names, made safe for Qt's AutoText
/// (which renders HTML, including remote images): no markup characters.
function plain(s) {
    if (s === undefined || s === null)
        return ""
    return String(s).replace(/</g, "\u2039").replace(/>/g, "\u203A")
}

/// Escape for places that intentionally use rich text.
function esc(s) {
    return String(s === undefined || s === null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
}

/// Session-bus names that can act outside the sandbox (mirrors
/// sam-core permissions::dangerous_bus_name; the core check is authoritative).
function dangerousBus(name) {
    const n = String(name).trim()
    if (n === "*" || n === "org.*" || n === "org.freedesktop.*" || n.indexOf("org.freedesktop.portal.*") === 0)
        return true
    const bad = ["org.freedesktop.systemd1", "org.freedesktop.Flatpak", "org.freedesktop.portal.Flatpak", "org.freedesktop.impl.portal.",
                 "org.kde.KWin", "org.kde.plasmashell", "org.kde.klauncher", "org.kde.kded", "org.kde.krunner", "org.kde.ksmserver",
                 "org.kde.kglobalaccel", "org.gnome.Shell", "org.gnome.SessionManager", "ca.desrt.dconf"]
    const prefix = n.endsWith("*") ? n.replace(/\.?\*$/, "") : null
    return bad.some(b => prefix !== null ? (b.indexOf(prefix) === 0 || prefix.indexOf(b.replace(/\.$/, "")) === 0) : n.indexOf(b) === 0)
}

/// `~/…` form of a path, unchanged otherwise: for values that are stored.
function tildifyRaw(path, home) {
    if (!path)
        return ""
    if (home && path.indexOf(home) === 0)
        return "~" + path.slice(home.length)
    return path
}

function tildify(path, home) {
    if (!path)
        return ""
    if (home && path.indexOf(home) === 0)
        return plain("~" + path.slice(home.length))
    return plain(path)
}

/// Point size for secondary text (paths, captions): one step below the
/// normal font, never below 7 pt.
function smallPointSize(font) {
    return Math.max(7, font.pointSize - 1)
}
