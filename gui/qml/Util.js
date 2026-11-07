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

const backendLabels = {
    "auto": "Automatic",
    "bubblewrap": "Bubblewrap",
    "bubblejail": "Bubblejail",
    "firejail": "Firejail",
    "unsandboxed": "Unsandboxed"
}

function iconUrl(path) {
    return path ? "file://" + path : ""
}

function tildify(path, home) {
    if (!path)
        return ""
    if (home && path.indexOf(home) === 0)
        return "~" + path.slice(home.length)
    return path
}
