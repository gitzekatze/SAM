// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.kirigamiaddons.formcard as FormCard

/// An enumerated permission with short options (folder access, system bus):
/// title and description on the left, a compact drop-down on the right.
FormCard.AbstractFormDelegate {
    id: d
    required property string key
    required property var editor
    /// [{ value: "none", text: "No access", description: "…" }, ...]
    required property var options
    property string overrideText: ""
    property string overrideDescription: ""
    property bool available: true

    readonly property var selectedOption: options[indexFor(editor.value(key))]

    objectName: "choice:" + key
    opacity: available ? 1 : 0.55
    enabled: editor.editable && available
    background: null
    Layout.fillWidth: true

    /// Select option `index`, as if picked in the drop-down.
    function choose(index) {
        editor.request(key, options[index].value)
    }

    function indexFor(v) {
        for (let i = 0; i < options.length; i++)
            if (options[i].value === v)
                return i
        return 0
    }

    contentItem: RowLayout {
        spacing: Kirigami.Units.largeSpacing
        ColumnLayout {
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing
            QQC2.Label {
                text: d.overrideText || d.editor.titleOf(d.key)
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            QQC2.Label {
                text: d.editor.describe(d.key, d.overrideDescription || (d.selectedOption && d.selectedOption.description ? d.selectedOption.description : ""))
                wrapMode: Text.Wrap
                color: Kirigami.Theme.disabledTextColor
                visible: text !== ""
                Layout.fillWidth: true
            }
        }
        RiskChip {
            shown: d.editor.activeRisk(d.key) !== ""
            level: d.editor.activeRisk(d.key) || "high"
            compact: true
        }
        QQC2.ComboBox {
            id: combo
            model: d.options
            textRole: "text"
            valueRole: "value"
            Layout.preferredWidth: Math.max(implicitWidth, Kirigami.Units.gridUnit * 9)
            Component.onCompleted: currentIndex = Qt.binding(() => d.indexFor(d.editor.value(d.key)))
            onActivated: function (index) {
                currentIndex = Qt.binding(() => d.indexFor(d.editor.value(d.key)))
                d.choose(index)
            }
        }
    }
}
