cmake_minimum_required(VERSION 3.21)
project(sam-jail-gui VERSION 0.1.0 LANGUAGES CXX)

# SAM GUI: a thin Qt6/QML/Kirigami shell over the Rust core.
# The shell talks to the core through `sam-jail --json ...` (see src/backend.cpp).

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Gui Widgets Qml Quick QuickControls2)
find_package(KF6Config REQUIRED)
find_package(KF6ColorScheme REQUIRED)
find_package(KF6Kirigami REQUIRED)

qt_standard_project_setup(REQUIRES 6.5)
if(QT_KNOWN_POLICY_QTP0004)
    qt_policy(SET QTP0004 NEW)
endif()

qt_add_executable(sam-jail-gui
    src/main.cpp
    src/backend.cpp src/backend.h
    src/thememanager.cpp src/thememanager.h
)

qt_add_qml_module(sam-jail-gui
    URI SAM
    VERSION 1.0
    QML_FILES
        qml/Main.qml
        qml/AppListPage.qml
        qml/AppPanel.qml
        qml/PermissionsEditor.qml
        qml/PermSwitch.qml
        qml/PermChoice.qml
        qml/PermChoiceInline.qml
        qml/PathListEditor.qml
        qml/PresetsPage.qml
        qml/PresetEditorPage.qml
        qml/SettingsPage.qml
        qml/DiagnosticsPage.qml
        qml/StatusBadge.qml
        qml/RiskChip.qml
        qml/Pill.qml
        qml/PrimaryButton.qml
        qml/WarningList.qml
        qml/ConfirmDialog.qml
        qml/AppIcon.qml
        qml/Util.js
    RESOURCES
        themes/breeze-light.colors
        themes/breeze-dark.colors
        themes/breeze-high-contrast.colors
        themes/cachyos-neon.colors
        icons/sam.svg
)

target_link_libraries(sam-jail-gui PRIVATE
    Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Qml Qt6::Quick Qt6::QuickControls2
    KF6::ConfigCore KF6::ColorScheme
)

install(TARGETS sam-jail-gui RUNTIME DESTINATION bin)
